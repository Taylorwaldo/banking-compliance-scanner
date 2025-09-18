"""
Financial Risk Quantification Engine for Cloud Security Compliance Scanner
Transforms technical compliance findings into business risk metrics and financial impact analysis

Author: Taylor Waldo
Version: 2.0.0
License: MIT
"""

import csv
import json
import logging
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from logging import CRITICAL
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import argparse
from enum import Enum

# Configures logging so messages show up in both on screen and in the file risk_analysis.log
# Ex. log line - 2025-09-10 16:32:00 - INFO - Loaded 25 failed finding

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('risk_analysis.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# Enums

# Defines supported compliance frameworks
class ComplianceFramework(Enum):
    PCI_DSS = "pci_dss_4.0"
    SOC2 = "soc2"
    CIS = "cis_1.5"

# Defines risk levels (name, color code, priority value)

# #FF0000 → pure red (Critical risk)
# #FF6600 → orange-ish (High risk)
# #FFAA00 → amber/yellow-orange (Medium risk)
# #FFFF00 → bright yellow (Low risk)
# #00FF00 → bright green (Info/low severity)


class RiskLevel(Enum):
    CRITICAL = ("Critical", "#FF0000", 4)
    HIGH = ("High", "#FF6600", 3)
    MEDIUM = ("Medium", "#FFAA00", 2)
    LOW = ("Low", "F#FFFF00", 1)
    INFO = ("Info", "#00FF00", 0)

# Dataclasses
# Finding = one row from the CSV (a compliance test result)

@dataclass
class Finding:
    # Each line inside the class defines a field with a type hint:
    # : str -> type hint saying the field should be a string
    # = "" -> default value if not provided (So control_id and resource_id are optional.)

    check_id: str
    status: str
    severity: str
    service: str
    region: str
    account_id: str
    description: str
    remediation: str
    compliance_framework: str
    control_id: str = ""
    resource_id: str = ""

    # is_failed property returns True if the check is a failure
    @property
    def is_failed(self) -> bool:
        return self.status.upper() in ("FAIL", "FAILED", "NON_COMPLIANT") # Checks the status field, converts it to uppercase
                                                                          # and returns True if the status is one of those failure values


# Stores calculated results for one finding: risk score, estimated costs, ROI, and such

@dataclass
class RiskMetrics:
    risk_score: int
    risk_level: RiskLevel
    financial_impact_min: float
    financial_impact_max: float
    financial_impact_likely: float
    remediation_cost: float
    roi_score: float
    business_impact: str
    regulatory_exposure: str
    customer_impact: str
    time_to_remediate_days: int

class FinancialImpactCalculator:
    """
    FinancialImpactCalculator

    This class hold all the math for turning severities into dollars and business impact

    Constants:
        PCI_FINES           -> fine ranges for PCi violations
        SOC2_IMPACT         -> expected churn %, contract loss %, etc.
        REMEDIATION_COSTS   -> average cost to fix depending on service
                                (e.g., S3 vs. IAM)

        Methods:
             calculate_pci_impact(severity)
             -> returns min, max, likely fine.

             calculate_soc2_impact(severity)
             -> returns financial impact from churn/contract loss

             calculate_remediation_cost(service, severity_
             -> looks up fix cost

             calculate_roi(impact, cost)
             -> (impact - cost) / cost.
    """

    # PCI-DSS fine ranges by merchant level and violation type
    PCI_FINES = {
        "CRITICAL": {
            "min": 50000,
            "max": 100000,
            "likely": 75000,
            "description": "Cardholder data exposure or encryption failures"
        },
        "HIGH": {
            "min": 25000,
            "max": 50000,
            "likely": 35000,
            "description": "Access control or monitoring failures"
        },
        "MEDIUM": {
            "min": 10000,
            "max": 25000,
            "likely": 15000,
            "description": "Configuration or maintenance issues"
        },
        "LOW": {
            "min": 5000,
            "max": 10000,
            "likely": 7500,
            "description": "Documentation or procedural gaps"
        }
    }

    # SOC 2 business impact calculations
    SOC2_IMPACT = {
        "CRITICAL": {
            "customer_churn_risk": 0.15,    # 15% of customers at risk
            "contract_value_risk": 0.25,    # 25% of contract value @ risk
            "reputation_score_impact": 40,
            "description": "Major trust boundary violations"
        },
        "HIGH": {
            "customer_churn_risk": 0.08,
            "contract_value_risk": 0.15,
            "reputation_score_impact": 25,
            "description": "Significant security control gaps"
        },
        "MEDIUM": {
            "customer_churn_risk": 0.03,
            "contract_value_risk": 0.08,
            "reputation_score_impact": 15,
            "description": "Moderate control weakness"
        },
        "LOW": {
            "customer_churn_risk": 0.01,
            "contract_value_risk": 0.03,
            "contract_score_impact": 5,
            "description": "Minor procedural issues"
        }
    }
# Average remediation costs by service & severity
# Top-level keys: "s3", "ec2", "rds", "iam", "vpc". "default"
#   -> Each represent a cloud service or a generic fallback aka default

REMEDIATION_COSTS = {
    "s3": {"CRITICAL": 5000, "HIGH": 3000, "MEDIUM": 1500, "LOW": 500},
    "ec2": {"CRITICAL": 8000, "HIGH": 5000, "MEDIUM": 2500, "LOW": 1000},
    "rds": {"CRITICAL": 10000, "HIGH": 6000, "MEDIUM": 3000, "LOW": 1200},
    "iam": {"CRITICAL": 4000, "HIGH": 2500, "MEDIUM": 1200, "LOW": 400},
    "vpc": {"CRITICAL": 6000, "HIGH": 3500, "MEDIUM": 1800, "LOW": 700},
    "default": {"CRITICAL": 5000, "HIGH": 3000, "MEDIUM": 1500, "LOW": 600},
}

# annual_revenue is the companys total yr revenue (default $50 mil)
# self.annual_revenue stores it so the other methods can use it in the calculations
# This below is the constructor for the class...
def __init__(self, annual_revenue: float = 50000000):
    """Initialize with company's annual revenue for impact calculations"""
    self.annual_revenue = annual_revenue


#---------------------------------------------------------------------------------------------------
# Purpose : Estimate the financial impact of the PCI-DSS violation based on severity.
# Converts -severity- to uppercase for consistency like for ex. "high" become "HIGH"
# Looks up the PCO_FINES dictionary to get:
#   Min fine
#   Max fine
#   Likely fine
# Returns a tuple (min, max, likely). Remember a tuple is immutable ie the values can't be changed
# If the severity isn't in the dictionary, it returns (0, 0, 0)
#---------------------------------------------------------------------------------------------------
def calculate_pci_impact(self, severity: str) -> Tuple[float, float, float]: # note2self severity: -> severity must be a string.
    """Calculate PCI-DSS financial impact ranges"""                             # -> Tuple[float, float, float] -> the function returns a tuple of three floats (min, max, likely)
    severity_upper = severity.upper()
    if severity_upper in self.PCI_FINES:
        fine_data = self.PCI_FINES[severity_upper]
        return fine_data["min"], fine_data["max"], fine_data["likely"]
    return 0,0,0


# Purpose: Estimate financial impact for SOC 2 compliance issues like customer churn or lost contracts
def calculate_soc2_impact(self, severity: str) -> Tuple[float, float, float]:
    """Calculate SOC2 business impact in financial terms"""

    # Convert severity to uppercase
    # Look up SOC2_IMPACT dict for that severity
    # ???
    # Profit... sike compute revenue loss...
    severity_upper = severity.upper()
    if severity_upper in self.SOC_IMPACT:
        impact_data = self.SOC2_IMPACT[severity_upper]

        # computing revenue loss...
        churn_impact = self.annual_revenue * impact_data["customer_churn_risk"] # estimated revenue lost if customers leave
        contract_impact = self.annual_revenue * impact_data["contract_value_risk"] # partial revenue lost from contract risks (scaled by 20%).

        # Compute min, max, & likely impacts:
        min_impact = min(churn_impact, contract_impact) * 0.5 # conservative lower bound
        max_impact = churn_impact + contract_impact # worst- case scenario
        likely_impact = (min_impact +max_impact) / 2

        return min_impact, max_impact, likely_impact
    return 0, 0, 0 # if severity not found


# Purpose: Estimate the cost to fix a finding, depending on cloud service & risk severity
def calculate_remediation_cost(self, service: str, severity: str):
    """See purpose above"""
    # Covert service name to lowercase & severity to uppercase
    service_lower = service.lower()
    severity_upper = severity.upper()

    #Returns the remediation cost from the matrix
    # If the service/severity isnt found, default to $1k
    cost_matrix = self.REMEDIATION_COSTS.get(service_lower, self.REMEDIATION_COSTS["default"])
    return cost_matrix.get(severity_upper, 1000)

    # Example: calculate_remediation_cost("s3". "CRITICAL") -> returns $5k

#---------------------------------------------------------------------------------------------------
# Purpose: Calculates return on investment aka R.O.I. of performing remediation.
# The formula :
#               financial impact avoided - remediation costs
#       ROI  =  ----------------------------------------
#                       remediation cost
# If the remediation cost is ZERO ... returns 0 to avoid division errors.
# Uses -round(...,2) to keep the result
# Example -> calculate_roi(75000, 5000) #  (75000-500)/5000 = 14.0
#       |> ROI of 14 meas $14 of impact avoided for every $1 spent fixing it.
#---------------------------------------------------------------------------------------------------
def calculate_roi(self, financial_impact: float, remediation_cost: float) -> float: # reminder 2 self -> is a type hint for the return value of a function, ie this function takes twi floats and will return a float
    if remediation_cost == 0:                                                           # returnsa single float representing the ROI
        return 0
    return round((financial_impact - remediation_cost) / remediation_cost, 2)



#---------------------------------------------------------------------------------------------------
# Logic (For now... SUBJECT TO CHANGE!!!!!!
#
# 1. Takes a CSV scan output from Prowler
# 2. Validates the file exists
# 3. Reads each row into a Finding Object
# 4. Filters only the failed findings
# 5. Stores them in self.findings
# 6. Logs success/failure for reporting
#
# Nutshell: it loads, parses, & filters scan results, preparing them for financial impact
#           calculations in the risk quantification engine.
#--------------------------------------------------------------------------------------------------
class RiskQuantifier:
    """Main risk quantification engine"""

    def __init__(self, annual_revenue: float = 50000000):
        self_calculator = FinancialImpactCalculator(annual_revenue) # create an instance of FinancialImpactCalculator to use 4 calculations
        self.findings: List[Finding] = []                           # empty list that will store all failed findings
        self.risk_metrics: Dict[str, RiskMetrics] = {}              # an empty dictionary that will store calculated risk metrics for each service or control

    # Takes a path 2 a CVS file as input (cvs_file: str)
    # Returns bool, indicating success (true) or faliure (false)
    def load_scan_results(self, csv_file: str) -> bool:
        """Parse Prowler CVS output"""
        try:
            csv_path = Path(csv_file) # converts string path into a Path obj from pathlib
            if not csv_path.exists():
                logger.error(f"CSV file is not found: {csv_file}") # writes error message to logger
                return False

            with open(csv_path, 'r', encoding='utf-8') as f: # opens the file safely (auto closes it after)
                reader = csv.DictReader(f)                   # reads CSV rows as dictionaries, so each column can be accessed by its header name

                # Loops over every row in the CSV
                # Creates a Finding object with all the relevant fields.
                # row.get('FIELD_NAME', default) = safely retrieves a column; if it doesnt exist, it uses a default value
                for row in reader:
                    finding = Finding(
                        check_id=row.get('CHECK_ID', ''),
                        status=row.get('STATUS', ''),
                        severity=row.get('SEVERITY', 'MEDIUM'),
                        service=row.get('SERVICE_NAME', 'unknown'),
                        region=row.get('REGION', 'global'),
                        account_id=row.get('ACCOUNT_ID', ''),
                        description=row.get('DESCRIPTION', ''),
                        remediation=row.get('REMEDIATION', ''),
                        compliance_framework=row.get('COMPLIANCE', 'general'),
                        control_id=row.get('CONTROL_ID', ''),
                        resource_id=row.get('RESOURCE_ID', '')
                    )

                    if finding.is_failed:
                        self.findings.append(finding)

            logger.info(f"Loaded {len(self.findings)} failed findings from {csv_file}") #logs # of failed findings successfully loaded, returns true to indicate success                                                                         # re
            return True

        # Catches any exceptions during the file reading/parsing process
        # Logs the error message s& returns False -> prevents the program from crashing
        except Exception as e:
            logger.error(f"Error loading CSv: {str(e)}")
            return False


    #Maps technical scan severity (HIGH,LOW) to a business-focused RiskLevel enum
    #Default is MEDIUM if the severity is unrecognized
    #Uses .upper() to make mapping case insensitive
    # Example. finding.severity = "high"
    #           finding.severity.upper() -> "HIGH"
    #           severity_map.get("HIGH" -> RiskLevel.HIGH
    def determine_finding_severity(self, finding: Finding) -> RiskLevel:
        """Map Technical severity  to business risk lvl"""
        severity_map = {                                        # Dictionary (mind you)
            "CRITICAL": RiskLevel.CRITICAL,
            "HIGH": RiskLevel.HIGH,
            "MEDIUM": RiskLevel.MEDIUM,
            "LOW": RiskLevel.LOW,
            "INFORMATIONAL": RiskLevel.INFO
        }
        return severity_map.get(finding.severity.upper(), RiskLevel.MEDIUM)


    def calculate_finding_metrics(self, finding: Finding) -> RiskMetrics:
        """Calculate comprehensive risk metrics for a single finding"""
        risk_level = self.determine_finding_severity(finding)

        # Calculate financial impact based on framework
        if "pci" in finding.compliance_framework.lower():
            min_impact, max_impact, likely_impact = self.calculator.calculate_pci_impact(finding.severity)
            regulatory_exposure = "PCI-DSS non-compliance fines"
        elif "soc" in finding.compliance_framework.lower():
            min_impact, max_impact, likely_impact = self.calculator.calculate_soc2_impact(finding.severity)
            regulatory_exposure = "SOC 2 attestation failure"
        else:
            min_impact, max_impact, likely_impact = self.calculator.calculate_pci_impact(finding.severity)
            regulatory_exposure = "General compliance violation"

        # Calculate remediation cost
        remediation_cost = self.calculator.calculate_remediation_cost(finding.service, finding.severity)

        # Calculate ROI
        roi_score = self.calculator.calculate_roi(likely_impact, remediation_cost)

        # Calculate risk score (0-100)
        risk_score = self._calculate_risk_score(risk_level, finding)

        # Determine business impact narrative
        business_impact = self._generate_business_impact(finding, risk_level)

        # Determine customer impact
        customer_impact = self._assess_customer_impact(finding, risk_level)

        # Estimate remediation time
        time_to_remediate = self._estimate_remediation_time(risk_level)

        # Return all metrics in structured object
        return RiskMetrics(
            risk_score=risk_score,
            risk_level=risk_level,
            financial_impact_min=min_impact,
            financial_impact_max=max_impact,
            financial_impact_likely=likely_impact,
            remediation_cost=remediation_cost,
            roi_score=roi_score,
            business_impact=business_impact,
            regulatory_exposure=regulatory_exposure,
            customer_impact=customer_impact,
            time_to_remediate_days=time_to_remediate
        )

    def _calculate_risk_score(self, risk_level: RiskLevel, finding: Finding) -> int:
        """Calculate 0-100 risk score based on multiple factors"""
        base_scores = {
            RiskLevel.CRITICAL: 90,
            RiskLevel.HIGH: 70,
            RiskLevel.MEDIUM: 50,
            RiskLevel.LOW: 30,
            RiskLevel.INFO: 10,
        }

        score = base_scores.get(risk_level, 50)

        # Adjust based on service criticality
        critical_services = ["rds", "s3", "iam", "kms"]
        if finding.service.lower() in critical_services:
            score += 10

        # Adjust based on data exposure risk
        if any(keyword in finding.description.lower()
               for keyword in ["encryption", "public", "exposed", "unencrypted", "credential"]):
            score += 15

        return min(100, score)

    def _generate_business_impact(self, finding: Finding, risk_level: RiskLevel) -> str:
        """Generate executive-friendly business impact statement"""
        service_impacts = {
            "s3": "data exposure and potential breach",
            "ec3": "compute infrastructure compromise",
            "rds": "database and customer data risk",
            "iam": "identity and access control weakness",
            "vpc": "network security boundary violation",
            "kms": "encryption key management failure"
        }

        impact_templates = {
            RiskLevel.CRITICAL: "CRITICAL: Immediate {} risk with potential for regulatory action and significant financial loss",
            RiskLevel.HIGH: "HIGH: Significant {} requiring urgent remediation to avoid compliance penalties",
            RiskLevel.MEDIUM: "MODERATE: {} that could escalate if not addressed within current quarter",
            RiskLevel.LOW: "LOW: Minor {} requiring scheduled remediation",
            RiskLevel.INFO: "INFORMATIONAL: Potential {} for review"
        }

        service_risk = service_impacts.get(finding.service.lower(), "security control gap")
        template = impact_templates.get(risk_level, "Security issue identified")

        return template.format(service_risk)

    def _assess_customer_impact(self, finding: Finding, risk_level: RiskLevel) -> str:
        """Assess potential customer impact"""
        time_estimates = {
            RiskLevel.CRITICAL: 1,
            RiskLevel.HIGH: 3,
            RiskLevel.MEDIUM: 7,
            RiskLevel.LOW: 14,
            RiskLevel.INFO: 30,
        }
        return time_estimates.get(risk_level, 7)

    def _estimate_remediation_time(self, risk_level: RiskLevel) -> int:
        """Estimate remediation time in days"""
        time_estimates = {
            RiskLevel.CRITICAL: 1,
            RiskLevel.HIGH: 3,
            RiskLevel.MEDIUM: 7,
            RiskLevel.LOW: 14,
            RiskLevel.INFO: 30
        }
        return time_estimates.get(risk_level, 7)

    def calculate_aggregate_risk(self) -> Dict:
        """Calculate organization-wide risk metrics"""
        # Handle empty case - ie there are no findings, return dictionary of zeroed-out metrics immediately.
        if not self.findings:
            return {
                "total_findings": 0,
                "overall_risk_score": 0,
                "total_financial_exposure": {"min": 0, "max": 0, "likely":  0}
            }
        # Initialize Totals
        total_min = 0
        total_max = 0
        total_likely = 0
        risk_scores = []

        # Initialize Severity Counter
        findings_by_severity = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }

        for finding in self.findings:
            metrics = self.calculate_finding_metrics(finding)
            self.risk_metrics[finding.check_id] = metrics

            # Adds up the financial impact estimate from each finding
            # Collect risk scores into a list for later averaging
            total_min += metrics.financial_impact_min
            total_max += metrics.financial_impact_max
            risk_scores.append(metrics.risk_score)

            #Count findings by severity
            # Increments the count of findings per severity
            findings_by_severity[finding.severity.upper()] = \
                findings_by_severity.get(finding.severity.upper(), 0) + 1   # .get() ensures it won't crash/KeyError

            # Calculate weighted avg risk score
            overall_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0

            # Build the final dict summarizing all metrics
            # round to format #s nicely
            return {
                "total_findings": len(self.findings),
                "findings_by_severity": findings_by_severity,
                "overall_risk_score": round(overall_risk_score, 1),
                "total_financial_exposure": {
                    "min": round(total_min, 2),
                    "max": round(total_max, 2),
                    "likely": round(total_likely, 2)
                },
                "risk_level": self._determine_overall_risk_level(overall_risk_score),
                "top_risks": self._identify_top_risks(5)
            }


    def _determine_overall_risk_level(self, score: float) -> str:
        """Determine overall organization risk level"""
        if score >= 80:
            return "CRITICAL - Immediate executive action required"
        elif score >= 60:
            return "HIGH - Significant compliance gaps requiring urgent attention"
        elif score >= 40:
            return "MODERATE - Multiple issues requiring planned remediation"
        elif score >= 20:
            return "LOW - Minor compliance gaps"
        else:
            return "MINIMAL - Strong compliance posture"

    def _identify_top_risks(self, count: int = 5) -> List[Dict]:
        """Identify top risks by financial impact"""
        # Sort the findings
        sorted_findings = sorted(
            self.findings,
            key=lambda f: self.risk_metrics.get(f.check_id, RiskMetrics(
                0, RiskLevel.LOW, 0, 0, 0, 0, 0, "", "", "", 0
            )).financial_impact_likely,
            reverse=True
        )[:count] # Slice to keep only the top count findings

        # Build top_risks list
        top_risks = []
        for finding in sorted_findings:
            metrics = self.risk_metrics.get(finding.check_id)
            if metrics:
                #Builds a dictionary
                top_risks.append({
                    "check_id": finding.check_id,                                       # the identifier
                    "service": finding.service,                                         # the service affected
                    "description": finding.description[:100] + "...",                   # trims log descriptions to 100 chars
                    "financial_impact": f"${metrics.financial_impact_likely:,.0f}",     # formatted as USD
                    "risk_score": metrics.risk_score,                                   # raw numeric risk score
                    "remediation_cost": f"${metrics.remediation_cost:,.0f}",            # also format to USD
                    "roi_score": metrics.roi_score                                      # return on investment score
                })                                                                      # appends that dict to top_risks

        return top_risks

    def prioritize_remediation_by_roi(self) -> List[Dict]:
        """Prioritize findings by ROI (return on investment)"""
        roi_findings = []

        for finding in self.findings:
            metrics = self.risk_metrics.get(finding.check_id)
            if metrics and metrics.roi_score > 0:
                roi_findings.append({
                    "check_id": finding.check_id,
                    "service": finding.service,
                    "severity": finding.severity,
                    "description": finding.description[:150] + "...",
                    "remediation": finding.remediation[:200] + "...",       # trims remediation plan to 200 char
                    "roi_score": metrics.roi_score,
                    "days_to_remediate": metrics.time_to_remediate_days,    # estimated time cost
                    "business_impact": metrics.business_impact              # description of business consequences
                })

        # Sort by ROI score descending
        # the reverse=Ture tells python (sort from largest to smallest instead of the norm smallest to largest)
        roi_findings.sort(key=lambda x: x["roi_score"], reverse=True)

        return roi_findings

    def generate_executive_summary(self) -> Dict:
        """Generate comprehensive executive summary"""
        aggregate = self.calculate_aggregate_risk()

        # Calculate remediation budget
        total_remediation_cost = sum(
            self.risk_metrics[f.check_id].remediation_cost
            for f in self.findings
            if f.check_id in self.risk_metrics
        )

        # Get prioritized remediations
        prioritized = self.prioritize_remediation_by_roi()

        # Quick wins (high ROI, low cost)
        # Picks only remediations with a high ROI (>5) and a low cost (<5000).
        quick_wins = [
            r for r in prioritized
            if r["roi_score"] > 5 and r["remediation_cost"] < 5000
        ][:3]

        # Return Summary Dictionary
        return {
            # current date/time in ISO 8601 format
            "scan_date": datetime.now().isoformat(),
            #Headline generated from risk data
            "executive_briefing": {
                "headline": self._generate_executive_headline(aggregate),
                "risk_posture": aggregate["risk_level"],
                # Financial Exposure
                "financial_exposure": {
                    "total_at_risk": f"${aggregate['total_financial_exposure']['likely']:,.0f}",
                    "range": f"${aggregate['total_financial_exposure']['min']:,.0f} - ${aggregate['total_financial_exposure']['max']:,.0f}"
                },
                # shows the total remediation cost calculated earlier
                "remediation_investment_required": f"${total_remediation_cost:,.0f}",
                # "Overall_risk_score" out of 100
                # .get("CRITICAL", 0) --> safe lookup
                "key_metrics": {
                    "overall_risk_score": f"{aggregate['overall_risk_score']}/100",
                    "critical_findings": aggregate["findings_by_severity"].get("CRITICAL", 0),
                    "high_findings": aggregate["findings_by_severity"].get("HIGH", 0),
                    "total_findings": aggregate["total_findings"]
                }
            },
            "strategic_recommendations": self._generate_strategic_recommendations(aggregate, prioritized),
            "quick_wins": quick_wins,
            "top_5_risks": aggregate["top_risks"],
            "remediation_roadmap": self._generate_remediation_roadmap(prioritized),
            "compliance_status": self._assess_compliance_status(aggregate)
        }


    def _generate_executive_headline(self, aggregate: Dict) -> str:
        """Generate attention-grabbing executive headline"""
        risk_score = aggregate["overall_risk_score"]
        exposure = aggregate["total_financial_exposure"]["likely"]

        if risk_score >= 80:
            return f"🚨 CRITICAL ALERT: ${exposure:,.0f} at immediate risk - Board notification recommended"
        elif risk_score >= 60:
            return f"⚠️ HIGH RISK: ${exposure:,.0f} compliance exposure requires urgent action"
        elif risk_score >= 40:
            return f"📊 MODERATE RISK: ${exposure:,.0f} potential exposure - remediation plan needed"
        else:
            return f"✅ ACCEPTABLE RISK: Limited exposure of ${exposure:,.0f} - maintain current controls"

    def _generate_strategic_recommendations(self, aggregate: Dict, prioritized: List[Dict]) -> List[str]:
        """Generate strategic recommendations for executives"""
        recommendations = []

        # Add Crisis Response if Critical Findings Exist
        if aggregate["findings_by_severity"].get("CRITICAL", 0) > 0:
            recommendations.append(
                "IMMEDIATE: Form crisis response team for critical findings - 24-48 hour remediation window"
            )

        # Add Emergency Budget if risk score is High
        if aggregate["overall_risk_score"] > 60:
            recommendations.append(
                "URGENT: Allocate emergency budget for high-priority remediations this quarter"
            )

        # add automation if too many findings
        # (manual handling would be too much)
        if len(prioritized) > 20:
            recommendations.append(
                "STRATEGIC: Implement automated compliance monitoring to prevent future violations"
            )

        # ROI-based recommendation
        # finds remediations with ROI score > 10
        # If there are any, it:
        # - Takes the top five (high_roi[:5]
        # - Sums their "financial_benefit"
        # - Appends a recommendation showing the potential dollar value of those fixes.
        high_roi = [p for p in prioritized if p["roi_score"] > 10]
        if high_roi:
            total_benefit = sum(p["financial_benefit"] for p in high_roi[:5])
            recommendations.append(
                f"OPPORTUNITY: Top 5 remediations offer ${total_benefit:,.0f} in risk reduction"
            )

        # Fall back case if no conditions above triggered
        if not recommendations:
            recommendations.append(
                "MAINTAIN: Continue current security practices and schedule quarterly assessments"
            )

        return recommendations

    def _generate_remediation_roadmap(self, prioritized: List[Dict]) -> Dict:
        """Generate phased remediation roadmap"""
        return {
            # Phase 1: Immediate
            # take all remediations that can be fixed within 1 day; take only the top 3
            "phase_1_immediate": {
                "timeline": "0-7 days",
                "items": [p for p in prioritized if p["days_to_remediate"] <= 1][:3],
                "focus": "Critical security gaps requiring immediate attention"
            },
            # Filter items that take between 2-7 days to remediate; cap @ 5 items
            "phase_2_short_term": {
                "timeline": "1-4 weeks",
                "items": [p for p in prioritized if 1 < p["days_to_remediate"] <= 7][:5],
                "focus": "High-priority issues with strong ROI"
            },
            # Filter items that take more than 7 days to remediate; cao @ 5 items
            "phase_3_quarterly": {
                "timeline": "1-3 months",
                "items": [p for p in prioritized if p["days_to_remediate"] > 7][:5],
                "focus": "Strategic improvements and compliance alignment"
            }
        }

    def _assess_compliance_status(self, aggregate: Dict) -> Dict:
        """Assess overall compliance status"""
        # Extract Counts: Looks up how many critical & high severity findings exist
        critical_count = aggregate["findings_by_severity"].get("CRITICAL", 0)
        high_count = aggregate["findings_by_severity"].get("HIGH", 0)

        # Compliance Status Rules

        # If there is any critical finding, you are straight up non-compliant
        if critical_count > 0:
            status = "NON-COMPLIANT"
            audit_readiness = "NOT READY - Critical gaps must be addressed"
        # 5 more high findings? Partially compliant, audit risk
        elif high_count > 5:
            status = "PARTIALLY COMPLIANT"
            audit_readiness = "AT RISK - Significant gaps identified"
        # if total findings exceed 20, not failing, but improve b4 audit
        elif aggregate["total_findings"] > 20:
            status = "NEEDS IMPROVEMENT"
            audit_readiness = "CONDITIONAL - Minor gaps to address"
        # substantially compliant/audit ready if none of the above gets triggered
        else:
            status = "SUBSTANTIALLY COMPLIANT"
            audit_readiness = "AUDIT READY - Minor findings only"

        # Return Compliance Report
        return {
            "status": status,
            "audit_readiness": audit_readiness,
            "next_audit_recommendation": self._recommend_audit_timing(aggregate)
        }

    def _recommend_audit_timing(self, aggregate: Dict) -> str:
        """Recommend when to schedule next audit"""
        if aggregate["overall_risk_score"] > 70:
            return "Delay audit 3-6 months until critical issues resolved"
        elif aggregate["overall_risk_score"] > 50:
            return "Schedule audit in 2-3 months after remediation"
        else:
            return "Ready for audit - schedule at convenience"

    def export_executive_report(self, output_file: str):
        """Export executive report as Markdown"""
        # Generate Summary
        summary = self.generate_executive_summary()

        # Prepare the output path
        # Path(output_file) -> turns the string into a Path Object thanks to pathlib
        output_path = Path(output_file)

        # makes sure the folder, where the file will go, exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write JSON file
        # Writes the summary dict as nicely printed JSON (indent=2 spaces)
        # If there are non-serializable objects (like datetime) convert them to string
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, default=str)

        logger.info(f"Executive report exported to {output_file}")
        return summary

    def export_markdown_report(self, output_file: str):
        """Export executive report as Markdown"""

        # This will be picked up eventually

        # Takes the executive summary data (which has been already generated elsewhere),
        # and then writes it into a well-structured Markdown file that looks like a formatted executive report.

        # 1. Setup

        # 2. Report Header

        # 3. Executive Briefing

        # 4. Key Metrics

        # 5. Strategic Recommendations

        # 6. Top 5 Financial Risk

        # 7. Quick Wins

        # 8. Compliance Status

        # 9. Remediation Roadmap



def main():
    """Main execution function, obviously"""

if __name__ == "__main__":
    main()


