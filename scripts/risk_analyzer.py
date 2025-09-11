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
