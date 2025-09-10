#!/bin/bash

# Financial Services Cloud Security Compliance Scanner
# Automated security assessment tool for financial instituions
# Supports PCI-DSS, S0=OC2, and baning industry security standards
#
# Author: Taylor Waldo
# Version: 1.0.0
# License: MIT

set -euo pipfail # Error handling: exit if - any command fails, trying to use undefined variables, then catch errors in command pipes


# Block 3: Directory Configuration
# Determine and save important folder locations so the script works
# regardless of where it is run:
# - SCRIPT_DIR:   folder where this script is located
# - PROJECT_ROOT: parent folder of the script directory (project root)
# - CONFIG_DIR:   "config" folder inside the project
# - REPORTS_DIR:  "reports" folder inside the project
# - LOG_FILE:     path to the log file inside the reports folder

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
readonly CONFIG_DIR="$PROJECT_ROOT/config"
readonly REPORTS_DIR="$PROJECT_ROOT/reports"
readonly LOG_FILE="$REPORTS_DIR/scanner.log"


# Block 4: Default Settings

ORGANIZATION_NAME="${ORG_NAME:-DefaultOrg}" # Use environment variable ORG_NAME, or "DefaultOrg" if not set
SCAN_DATE=$(date +%Y-%m-%d_%H-%M-%S) # Gets date
OUTPUT_DIR="$REPORT_DIR/daily/$SCAN_DATE" # Create Timestamp
COMPLIANCE_FRAMEWORK="pci_dss_4.0" # Sets Default compliance to PCI-DSS
VERBOSE=false

# Block 5: Color Definitions - ANSI color codes for terminal output

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'	# NC - No Color: Resets color back to normal


# Block 6: Logging Functions
# Logging functions for the script:
# - log(): prints a timestamped message to the terminal and appends it to the log file.
# - log_info(), log_warn(), log_error(): print color-coded messages (INFO, WARN, ERROR)
#   and append them to the log file.
#
# AAA framework tie-in (Security+, CompTIA):
# - Authentication: logs help track who ran the script or triggered actions.
# - Authorization: warning/error logs can show attempted or denied actions.
# - Accounting: every action is timestamped and recorded, providing an audit trail
#   for accountability and later review.

log() {
	echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

log_info() {
	echo -e "${GREEN}[INFO]${NC} $1" | tee -a "LOG_FILE"
}

log_warn() {
	echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "LOG_FILE"
}

log_error() {
	echo -e "${RED}[ERROR]${NC} $1" | tee -a "LOG_FILE"
}


# Block 7: Header Display Function

print_header() {
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BLUE} $1${NC}"								        # $1 is the header text passed to the function
    echo -e "${BLUE}================================================================${NC}"
}

# Block 8: Usage/Help Function

usage() {
	cat << EOF										# Creates multi-line
Financia Sercices Cloud Security Compliance Scanner

USAGE:
	$(basename "$0") [OPTIONS]								# Shows script name in usage examples

OPTIONS:
	-f, --framework FRAMEWORK	Compliance framework (pci_dss_4.0, soc_cc, cis_1.5)
	-o, --org-name NAME		Organization name for reports
	-r, --region REGION		AWS region to scan (default:us-east-1)
	-v, --verbose			Enable bverbose output
	-h, --help			Show this help message
...
EOF
}

# Block 9: Argument Parsing

# parse_args(): Parses command-line arguments for the script.
# Supports the following flags:
#   -f, --framework   : Sets the compliance framework (requires a value, e.g., "pci_dss_4.0")
#   -o, --org-name    : Sets the organization name (requires a value)
#   -r, --region      : Sets the AWS region (requires a value)
#   -v, --verbose     : Enables verbose output (no value required)
#   -h, --help        : Displays usage information and exits
#
# Flags that take values use 'shift 2' to remove both the flag and its value from $@.
# Flags without values use 'shift' to remove just the flag.
# Unknown flags are logged as errors, usage is shown, and the script exits.

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -f|--framework)
                COMPLIANCE_FRAMEWORK="$2"
                shift 2
                ;;
            -o|--org-name)
                ORGANIZATION_NAME="$2"
                shift 2
                ;;
            -r|--region)
                AWS_DEFAULT_REGION="$2"
                export AWS_DEFAULT_REGION
                shift 2
                ;;
            -v|--verbose)			# Processing a flag with out a value 
                VERBOSE=true
                shift
                ;;
            -h|--help)				# Help Flag
                usage
                exit 0
                ;;
            *)					# Unknown Argument
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}


# Block 10: Prerequisites
# check_prerequisites(): Ensures all required tools and credentials are available before running the script.
# - Verifies that Prowler is installed using `command -v prowler`. 
#   Output is redirected to /dev/null to suppress it; exits with an error if not found.
# - Verifies that AWS CLI credentials are configured using `aws sts get-caller-identity`. 
#   Output is redirected to /dev/null to suppress it; exits with an error if the command fails.
# - Creates the output directory if it doesn't exist.
# - Logs the AWS account ID, AWS user ARN, and output directory for auditing.
# Exits with an error if any prerequisite is missing.

check_prerequisites() {
	log_info "Performing prerequisite checks..."		# Calls the log_info function

	if ! command -v prowler &> /dev/null; then
		log_error "Prowler is not installed. Please install with: pipx install prowler"
		exit 1
	fi

	if ! aws sts get-caller-identity &> /dev/null; then
		log_error "AWS credentials not configured. Please run 'aws configure'"
		exit 1
	fi

	mkdir -p "$OUTPUT_DIR"

	local aws_account=$(aws sts get-caller-identity --query Account --output text)
	local aws_user=$(aws sts get-caller-identity --query Arn --output text)

	log_info "AWS Account: $aws_account"
	log_info "AWS User: $aws_user"
	log_info "Output Directory: $OUTPUT_DIR"
}


# Block 11: Main Scan Function

# run_compliance_scan(): Performs a compliance scan using Prowler for a specified framework.
# Arguments:
#   $1 : Compliance framework name (e.g., pci_dss_4.0)
# Actions:
#   - Runs Prowler against AWS to check compliance.
#   - Saves reports in OUTPUT_DIR with filename <framework>_scan.
#   - Outputs reports in JSON, CSV, and HTML formats for automation, analysis, and readability.
#   - Logs success or failure and returns 0 on success, 1 on failure.

run_compliance_scan() {
	local framework="$1"
	local scan_name="${framework}_scan"

	log_info "Starting $framework compliance scan..."

	if prowler aws \
		--compliance "$framework" \
		--output-directory "$OUTPUT_DIR" \
		--output-filename "$scan_name" \
		--output-format json,cvs,html; then

		log_info "$framework scan completed successfully"
		return 0
	else
		log_error "$framework scan failed"
		return 1
	fi
}

# Block 12: Executive Summary Generator
# generate_executive_summary(): Creates a Markdown executive summary for the compliance scan.
# - Writes organization, scan date, and compliance framework information into 
#   $OUTPUT_DIR/executive_summary.md.
# - Uses a here-document (<< EOF) to embed multiline text with variable expansion.
# - Logs start and completion messages using log_info.

generate_executive_summary() {
	local summary_file="$OUTPUT_DIR/executive_summary.md"

	log_info "Generating executive summary..."

	cat > "$summary_file" << EOF

# Cloud Security Compliance Assessment Report

**Organization:** $ORGANIZATION_NAME
**Scan Date:** $(date '+%Y-%m-%d %H:%M:%S')  
**Framework:** $COMPLIANCE_FRAMEWORK  
...
EOF

    log_info "Executive summary generated: $summary_file"	# Log completion
}


# Block 13 : Metris Calculator

calculate_metrics() {
    local csv_file="$OUTPUT_DIR/${COMPLIANCE_FRAMEWORK}_scan.csv"
    
    if [[ -f "$csv_file" ]]; then
        local total_checks=$(tail -n +2 "$csv_file" | wc -l)
        local passed_checks=$(tail -n +2 "$csv_file" | grep -c "PASS" || true)
        local failed_checks=$(tail -n +2 "$csv_file" | grep -c "FAIL" || true)
        
        local compliance_percentage=$(( (passed_checks * 100) / total_checks ))
        
        echo "Compliance Score: ${compliance_percentage}%"
        
        if [[ $failed_checks -eq 0 ]]; then
            log_info "✅ EXCELLENT: Full compliance achieved"
        elif [[ $failed_checks -lt 5 ]]; then
            log_warn "⚠️  GOOD: Minor compliance gaps identified"
        else
            log_error "🚨 HIGH RISK: Significant compliance gaps identified"
        fi
    fi
}

# Block 14: Main Execution Function

# main(): Main program logic for the Cloud Security Compliance Scanner.
#
# Workflow:
# 1. parse_args "$@": Passes all command-line arguments ($@) to parse_args.
#    - $@ is a special Bash variable representing **all arguments passed to the script or function**.
#    - Using "$@" preserves argument boundaries (quotes around each argument) to avoid word splitting.
# 2. mkdir -p ...: Creates daily, monthly, and executive report directories if they don't exist.
# 3. print_header: Prints a stylized header for the scanner.
# 4. check_prerequisites: Ensures all required tools (Prowler, AWS credentials) are available.
# 5. run_compliance_scan: Performs the compliance scan for the chosen framework.
#    - If successful:
#       - generate_executive_summary: Creates a Markdown summary report.
#       - calculate_metrics: Computes summary metrics from the scan results.
#       - print_header: Displays a success message.
#    - If the scan fails, logs an error and exits with status 1.
#
# Notes on Bash syntax used here:
# - "$@" preserves all command-line arguments as separate words.
# - if ...; then ... else ... fi is the standard Bash conditional structure.
# - Functions are called simply by their name followed by arguments (no parentheses required in Bash).
 

main() {
    parse_args "$@"
    
    mkdir -p "$REPORTS_DIR/daily" "$REPORTS_DIR/monthly" "$REPORTS_DIR/executive"
    
 Block 13 : Metris Calculator

calculate_metrics() {
    local csv_file="$OUTPUT_DIR/${COMPLIANCE_FRAMEWORK}_scan.csv"
    
    if [[ -f "$csv_file" ]]; then
        local total_checks=$(tail -n +2 "$csv_file" | wc -l)
        local passed_checks=$(tail -n +2 "$csv_file" | grep -c "PASS" || true)
        local failed_checks=$(tail -n +2 "$csv_file" | grep -c "FAIL" || true)
        
        local compliance_percentage=$(( (passed_checks * 100) / total_checks ))
        
        echo "Compliance Score: ${compliance_percentage}%"
        
        if [[ $failed_checks -eq 0 ]]; then
            log_info "✅ EXCELLENT: Full compliance achieved"
        elif [[ $failed_checks -lt 5 ]]; then
            log_warn "⚠  GOOD: Minor compliance gaps identified"
        else
            log_error "🚨 HIGH RISK: Significant compliance gaps identified"
        fi
    fi
}
    print_header "CLOUD SECURITY COMPLIANCE SCANNER"
    
    check_prerequisites
    
    if run_compliance_scan "$COMPLIANCE_FRAMEWORK"; then
        generate_executive_summary
        calculate_metrics
        
        print_header "SCAN COMPLETED SUCCESSFULLY"
    else
        log_error "Compliance scan failed"
        exit 1
    fi
}

# Block 15: Script Entry Point

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
