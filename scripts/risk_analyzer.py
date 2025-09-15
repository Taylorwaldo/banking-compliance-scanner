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

    """
    Purpose:
        Generate all the risk metrics for a single finding and produce aggregate
        organizational risk reports.

    Steps/Logic:
        - Determine risk level using determine_finding_severity.
        - Calculate financial impact based on compliance framework (PCI, SOC2, or default).
        - Calculate remediation cost (calculator.calculate_remediation_cost).
        - Calculate ROI (calculator.calculate_roi).
        - Calculate risk score using _calculate_risk_score.
        - Generate business impact narrative (_generate_business_impact).
        - Assess customer impact (_assess_customer_impact).
        - Estimate remediation time (_estimate_remediation_time).
        - Returns a RiskMetrics object containing all above metrics.

    Private Helper Methods:
        _calculate_risk_score:
            Converts enum + finding info into 0-100 risk score.
            Adjusts for critical services and keywords in description.
        _generate_business_impact:
            Converts risk & service into a narrative statement for executives.
        _assess_customer_impact:
            Short summary of potential impact to customers based on severity.
        _estimate_remediation_time:
            Maps risk level to expected days to remediate.

    Syntax Notes:
        - "_" prefix → private/internal method convention in Python.
        - Dictionary lookups often use .get() with defaults.

    Aggregate Methods:
        calculate_aggregate_risk:
            Loops through all findings, calculates metrics, sums financial impact,
            and produces overall organizational risk score.
        _determine_overall_risk_level:
            Converts overall score into textual risk levels (CRITICAL, HIGH, MODERATE…).
        _identify_top_risks:
            Returns the top N findings by financial impact.

    ROI Prioritization:
        prioritize_remediation_by_roi:
            Sorts findings by ROI score to show quick wins first.
            Returns a list of dictionaries with ROI info, remediation cost,
            days to remediate, and business impact.

    Executive Summary Generation:
        generate_executive_summary:
            Aggregates all metrics into a structured dictionary.
            Includes:
                - headline → attention-grabbing summary
                - risk_posture → overall risk description
                - financial_exposure → total exposure and ranges
                - key_metrics → counts of findings by severity
                - strategic_recommendations → actionable recommendations
                - quick_wins → top high-ROI findings
                - top_5_risks → largest financial exposures
                - remediation_roadmap → phased remediation plan
                - compliance_status → overall compliance posture

        Helper Methods:
            _generate_executive_headline, _generate_strategic_recommendations,
            _generate_remediation_roadmap, _assess_compliance_status,
            _recommend_audit_timing all support executive reporting.

    Export Methods:
        export_executive_report:
            Saves summary as JSON.
        export_markdown_report:
            Saves summary as Markdown with tables, headings, and formatted financials.
    """

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

    def _estimate_remediation_time(self, risk_level: RiskLevel): -> int:
        """Estimate remediation time in days"""

    def calculate_aggregate_risk(self) -> Dict:
        """Calculate organization-wide risk metrics"""

    def _determine_overall_risk_level(self, score: float) -> str:
        """Determine overall organization risk level"""

    def _identify_top_risks(self, count: int = 5) -> List[Dict]:
        """Identify top risks by financial impact"""

    def prioritize_remediation_by_roi(self) -> List[Dict]:
        """Prioritize findings by ROI (return on investment)"""

    def generate_executive_summary(self) -> Dict:
        """Generate comprehensive executive summary"""

    def _generate_executive_headline(self, aggregate: Dict) -> str:
        """Generate attention-grabbing executive headline"""

    def _generate_strategic_recommendations(self, aggregate: Dict, prioritized: List[Dict]) -> List[str]:
        """Generate strategic recommendations for executives"""

    def _generate_remediation_roadmap(self, prioritized: List[Dict]) -> Dict:
        """Generate phased remediation roadmap"""

    def _assess_compliance_status(self, aggregate: Dict) -> Dict:
        """Assess overall compliance status"""

    def _recommend_audit_timing(self, aggregate: Dict) -> str:
        """Recommend when to schedule next audit"""

    def export_executive_report(self, output_file: str):
        """Export executive report as Markdown"""

        # holy shit LOL

def main():
    """Main execution function, obviously"""

if __name__ == "__main__":
    main()


