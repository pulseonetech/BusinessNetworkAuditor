#!/bin/bash

# macOSWorkstationAuditor - Report Export Module
# Version 1.0.0

# Global variables for report generation (bash 3.2 compatible)
ALL_FINDINGS=()
RISK_COUNT_HIGH=0
RISK_COUNT_MEDIUM=0
RISK_COUNT_LOW=0
RISK_COUNT_INFO=0

export_markdown_report() {
    log_message "INFO" "Generating technician report..." "REPORT"

    # Generate technician report (matching Windows format) - findings already collected
    local report_file="$OUTPUT_PATH/${BASE_FILENAME}_technician_report.md"
    
    generate_markdown_header > "$report_file"
    generate_executive_summary >> "$report_file"
    generate_critical_action_items >> "$report_file"
    generate_system_overview >> "$report_file"
    generate_system_resources >> "$report_file"
    generate_network_interfaces >> "$report_file"
    generate_security_management >> "$report_file"
    generate_security_analysis >> "$report_file"
    generate_software_inventory >> "$report_file"
    generate_recommendations >> "$report_file"
    generate_markdown_footer >> "$report_file"
    
    log_message "SUCCESS" "Technician report generated: $report_file" "REPORT"
}

export_raw_data_json() {
    log_message "INFO" "Generating JSON raw data export..." "REPORT"

    # Use findings already collected - don't collect again
    local json_file="$OUTPUT_PATH/${BASE_FILENAME}_raw_data.json"
    
    # Generate JSON structure matching Windows version format
    cat > "$json_file" << EOF
{
  "metadata": {
    "computer_name": "$COMPUTER_NAME",
    "audit_timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
    "tool_version": "$CONFIG_VERSION",
    "platform": "macOS",
    "os_version": "$(sw_vers -productVersion)",
    "os_build": "$(sw_vers -buildVersion)",
    "audit_duration_seconds": $(($(date +%s) - START_TIME))
  },
  "system_context": {
    "os_info": {
      "caption": "$(sw_vers -productName) $(sw_vers -productVersion)",
      "version": "$(sw_vers -productVersion)",
      "build_number": "$(sw_vers -buildVersion)",
      "architecture": "$(uname -m)",
      "last_boot_time": "$(date -r $(sysctl -n kern.boottime | awk '{print $4}' | tr -d ',') '+%Y-%m-%d %H:%M:%S')"
    },
    "hardware_info": {
      "model": "$(sysctl -n hw.model)",
      "total_memory_gb": $(echo "scale=2; $(sysctl -n hw.memsize) / 1073741824" | bc),
      "cpu_cores": $(sysctl -n hw.ncpu)
    },
    "domain": "$(hostname | cut -d. -f2- || echo 'WORKGROUP')",
    "computer_name": "$COMPUTER_NAME"
  },
  "compliance_framework": {
    "findings": [
EOF

    # Add all findings as JSON
    local first_finding=true
    for finding in "${ALL_FINDINGS[@]}"; do
        # Parse JSON finding using native bash/sed/awk (no Python dependency)
        local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
        local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
        local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
        local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
        
        # Set defaults if parsing failed
        [[ -z "$category" ]] && category="Unknown"
        [[ -z "$item" ]] && item="Unknown"
        [[ -z "$value" ]] && value="Unknown"
        [[ -z "$risk_level" ]] && risk_level="INFO"

        # Skip empty or malformed entries
        if [[ "$item" == "Unknown" && "$value" == "Unknown" ]]; then
            continue
        fi

        # Write comma separator before each finding except the first valid one
        if [[ "$first_finding" == true ]]; then
            first_finding=false
        else
            echo "," >> "$json_file"
        fi

        # Generate finding ID
        local finding_id="macOS-$(echo "$category$item" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | tr -cd '[:alnum:]-')"
        
        cat >> "$json_file" << EOF
      {
        "finding_id": "$finding_id",
        "category": "$category",
        "item": "$item",
        "value": "$value",
        "requirement": "$details",
        "risk_level": "$risk_level",
        "recommendation": "$recommendation",
        "framework": "macOS_Security_Assessment"
      }
EOF
    done

    cat >> "$json_file" << EOF
    ]
  },
  "summary": {
    "total_findings": ${#ALL_FINDINGS[@]},
    "risk_distribution": {
      "HIGH": $RISK_COUNT_HIGH,
      "MEDIUM": $RISK_COUNT_MEDIUM,
      "LOW": $RISK_COUNT_LOW,
      "INFO": $RISK_COUNT_INFO
    }
  }
}
EOF

    log_message "SUCCESS" "JSON raw data exported: $json_file" "REPORT"
}

collect_all_findings() {
    log_message "INFO" "Collecting findings from all modules..." "REPORT"
    
    # Initialize arrays and counters
    ALL_FINDINGS=()
    RISK_COUNT_HIGH=0
    RISK_COUNT_MEDIUM=0
    RISK_COUNT_LOW=0
    RISK_COUNT_INFO=0
    
    # Collect findings from each module if functions exist
    local module_functions=(
        "get_system_findings"
        "get_security_findings"
        "get_software_findings"
        "get_network_findings"
        "get_user_findings"
        "get_patch_findings"
        "get_disk_findings"
        "get_memory_findings"
        "get_process_findings"
    )
    
    for func in "${module_functions[@]}"; do
        if declare -f "$func" >/dev/null 2>&1; then
            log_message "INFO" "Collecting findings from $func..." "REPORT"
            while IFS= read -r finding; do
                if [[ -n "$finding" ]]; then
                    ALL_FINDINGS+=("$finding")
                    
                    # Count risk levels using native bash
                    local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
                    [[ -z "$risk_level" ]] && risk_level="INFO"
                    case "$risk_level" in
                        "HIGH") ((RISK_COUNT_HIGH++)) ;;
                        "MEDIUM") ((RISK_COUNT_MEDIUM++)) ;;
                        "LOW") ((RISK_COUNT_LOW++)) ;;
                        *) ((RISK_COUNT_INFO++)) ;;
                    esac
                fi
            done < <($func 2>/dev/null || echo "")
        fi
    done
    
    log_message "SUCCESS" "Collected ${#ALL_FINDINGS[@]} total findings" "REPORT"
}

generate_markdown_header() {
    cat << EOF
# macOS Workstation Security Audit Report

**Computer:** $COMPUTER_NAME
**Generated:** $(date '+%Y-%m-%d %H:%M:%S')
**Tool Version:** macOS Workstation Auditor v$CONFIG_VERSION

EOF
}

generate_executive_summary() {
    cat << EOF
## Executive Summary

| Risk Level | Count | Priority |
|------------|-------|----------|
| HIGH | $RISK_COUNT_HIGH | Immediate Action Required |
| MEDIUM | $RISK_COUNT_MEDIUM | Review and Plan Remediation |
| LOW | $RISK_COUNT_LOW | Monitor and Maintain |
| INFO | $RISK_COUNT_INFO | Informational |

EOF
}

generate_critical_action_items() {
    # Only generate this section if there are HIGH or MEDIUM risk items
    if [[ $RISK_COUNT_HIGH -gt 0 || $RISK_COUNT_MEDIUM -gt 0 ]]; then
        cat << EOF
## Critical Action Items

EOF
        
        if [[ $RISK_COUNT_HIGH -gt 0 ]]; then
            cat << EOF
### HIGH PRIORITY (Immediate Action Required)

EOF
            for finding in "${ALL_FINDINGS[@]}"; do
                local finding_risk=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
                [[ -z "$finding_risk" ]] && finding_risk="INFO"
                
                if [[ "$finding_risk" == "HIGH" ]]; then
                    local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
                    local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
                    local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
                    local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
                    local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
                    
                    [[ -z "$category" ]] && category="Unknown"
                    [[ -z "$item" ]] && item="Unknown"
                    [[ -z "$value" ]] && value="Unknown"
                    
                    cat << EOF
- **$category - $item:** $value
  - Details: $details
EOF
                    if [[ -n "$recommendation" ]]; then
                        cat << EOF
  - Recommendation: $recommendation
EOF
                    fi
                    echo ""
                fi
            done
        fi
        
        if [[ $RISK_COUNT_MEDIUM -gt 0 ]]; then
            cat << EOF
### MEDIUM PRIORITY (Review and Plan)

EOF
            for finding in "${ALL_FINDINGS[@]}"; do
                local finding_risk=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
                [[ -z "$finding_risk" ]] && finding_risk="INFO"
                
                if [[ "$finding_risk" == "MEDIUM" ]]; then
                    local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
                    local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
                    local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
                    local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
                    local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
                    
                    [[ -z "$category" ]] && category="Unknown"
                    [[ -z "$item" ]] && item="Unknown"
                    [[ -z "$value" ]] && value="Unknown"
                    
                    cat << EOF
- **$category - $item:** $value
  - Details: $details
EOF
                    if [[ -n "$recommendation" ]]; then
                        cat << EOF
  - Recommendation: $recommendation
EOF
                    fi
                    echo ""
                fi
            done
        fi
    fi
}

generate_additional_information() {
    # Get LOW and INFO items, grouped by category, excluding categories that appear in Critical Action Items
    local additional_items=()
    local critical_categories=()
    
    # Debug: Log the number of findings we're starting with
    log_message "INFO" "Total findings to process: ${#ALL_FINDINGS[@]}" "REPORT"
    
    # First, collect categories that appear in HIGH/MEDIUM findings
    for finding in "${ALL_FINDINGS[@]}"; do
        local finding_risk=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
        [[ -z "$finding_risk" ]] && finding_risk="INFO"
        
        if [[ "$finding_risk" == "HIGH" || "$finding_risk" == "MEDIUM" ]]; then
            local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
            [[ -n "$category" ]] && critical_categories+=("$category")
        fi
    done
    
    # Collect LOW and INFO items not in critical categories
    for finding in "${ALL_FINDINGS[@]}"; do
        local finding_risk=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
        [[ -z "$finding_risk" ]] && finding_risk="INFO"
        
        if [[ "$finding_risk" == "LOW" || "$finding_risk" == "INFO" ]]; then
            local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
            local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
            
            # Check if this category appears in critical findings
            local is_critical_category=false
            for crit_cat in "${critical_categories[@]}"; do
                if [[ "$category" == "$crit_cat" ]]; then
                    is_critical_category=true
                    break
                fi
            done
            
            # Exclude items that appear in dedicated sections
            local is_dedicated_section_item=false

            # Exclude System Configuration items
            if [[ "$category" == "System" ]]; then
                case "$item" in
                    "Operating System"|"Hardware"|"Computer Name"|"System Uptime"|"Time Machine Backups"|"Backup Solutions")
                        is_dedicated_section_item=true
                        ;;
                esac
            fi

            # Exclude Management items (now in System Configuration)
            if [[ "$category" == "Management" ]]; then
                case "$item" in
                    "MDM Enrollment"|"Apple Business Manager"|"Device Supervision"|"Configuration Profiles")
                        is_dedicated_section_item=true
                        ;;
                esac
            fi

            # Exclude Process items (now in Process Analysis)
            if [[ "$category" == "Process" ]]; then
                case "$item" in
                    "Process Activity"|"Top 5 Process CPU Usage"|"Top 5 Process Memory Usage")
                        is_dedicated_section_item=true
                        ;;
                esac
            fi

            # Exclude Memory items (now in Memory Analysis)
            if [[ "$category" == "Memory" ]]; then
                case "$item" in
                    "Memory Usage"|"Top 5 Process Memory Usage"|"Memory Pressure")
                        is_dedicated_section_item=true
                        ;;
                esac
            fi

            # Exclude Storage items (now in Disk Analysis) but allow Directory items to remain excluded
            if [[ ("$category" == "Storage" || "$item" =~ "Disk") && ! "$item" =~ "Directory:" ]]; then
                is_dedicated_section_item=true
            fi

            # Always exclude directory listings (unwanted fluff)
            if [[ "$item" =~ "Directory:" ]]; then
                is_dedicated_section_item=true
            fi

            # Exclude Network items (now in Network Analysis)
            if [[ "$category" == "Network" ]]; then
                case "$item" in
                    "Active Interfaces"|"Primary IP Address"|"Wi-Fi Status"|"Saved Wi-Fi Networks"|"DNS Servers"|"Listening Services"|"Sharing Services"|"VPN Configuration"|"High-Risk Listening Ports")
                        is_dedicated_section_item=true
                        ;;
                esac
            fi

            # Always exclude established connections (unwanted noise)
            if [[ "$item" == "Established Connections" ]]; then
                is_dedicated_section_item=true
            fi

            # Exclude port findings (now in Network Analysis)
            if [[ "$item" =~ "Port " && "$category" == "Network" ]]; then
                is_dedicated_section_item=true
            fi

            # Include only non-critical categories and non-dedicated section items - no duplicates allowed
            if [[ "$is_critical_category" == false && "$is_dedicated_section_item" == false ]]; then
                additional_items+=("$finding")
            fi
        fi
    done
    
    if [[ ${#additional_items[@]} -gt 0 ]]; then
        cat << EOF
## Additional Information

EOF
        
        # Group by category and only output categories that have items
        local categories=()
        log_message "INFO" "Additional items count: ${#additional_items[@]}" "REPORT"
        
        for finding in "${additional_items[@]}"; do
            local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
            [[ -z "$category" ]] && category="Unknown"
            
            log_message "INFO" "Found category: '$category' from finding: $(echo "$finding" | cut -c1-100)..." "REPORT"
            
            # Add to categories if not already present
            local category_exists=false
            for existing_cat in "${categories[@]}"; do
                if [[ "$existing_cat" == "$category" ]]; then
                    category_exists=true
                    break
                fi
            done
            [[ "$category_exists" == false ]] && categories+=("$category")
        done
        
        log_message "INFO" "Categories collected: ${categories[*]}" "REPORT"
        
        # Sort and output categories, but only if they have items
        for category in $(printf '%s\n' "${categories[@]}" | sort); do
            # First check if this category actually has items
            local category_has_items=false
            for finding in "${additional_items[@]}"; do
                local finding_category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
                [[ -z "$finding_category" ]] && finding_category="Unknown"
                
                if [[ "$finding_category" == "$category" ]]; then
                    category_has_items=true
                    break
                fi
            done
            
            # Only output the category if it has items
            if [[ "$category_has_items" == true ]]; then
                cat << EOF
### $category

EOF
                
                for finding in "${additional_items[@]}"; do
                    local finding_category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
                    [[ -z "$finding_category" ]] && finding_category="Unknown"
                    
                    if [[ "$finding_category" == "$category" ]]; then
                        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
                        local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
                        local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
                        local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
                        local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
                        
                        [[ -z "$item" ]] && item="Unknown"
                        [[ -z "$value" ]] && value="Unknown"
                        [[ -z "$risk_level" ]] && risk_level="INFO"
                        
                        # Skip empty or malformed entries
                        if [[ "$item" == "Unknown" && "$value" == "Unknown" ]]; then
                            continue
                        fi
                        
                        local risk_icon="[INFO]"
                        [[ "$risk_level" == "LOW" ]] && risk_icon="[LOW]"
                        
                        cat << EOF
**$risk_icon $item:** $value

- **Details:** $details
EOF
                        if [[ -n "$recommendation" ]]; then
                            cat << EOF
- **Recommendation:** $recommendation
EOF
                        fi
                        echo ""
                    fi
                done
            fi
        done
    fi
}

generate_system_overview() {
    cat << EOF
## System Overview

EOF

    # Core system identification - no duplicates, clean format
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Operating System" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Operating System:** $value - $details"
            break
        fi
    done

    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Hardware" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Hardware:** $value - $details"
            break
        fi
    done

    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Computer Name" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Computer Name:** $value - $details"
            break
        fi
    done

    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "System Uptime" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Uptime:** $value - $details"
            break
        fi
    done

    # Updates section (moved here from buried location)
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Available Updates" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Updates:** $value - $details"
            break
        fi
    done

    echo ""
}

generate_system_resources() {
    cat << EOF
## System Resources

EOF

    # Memory - show once, no duplicates
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Memory Usage" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Memory Usage:** $value - $details"
            break
        fi
    done

    # Top memory processes - show once
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Top 5 Process Memory Usage" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Top Memory Processes:** $value - $details"
            break
        fi
    done

    # Top CPU processes - show if available for consistency
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Top 5 Process CPU Usage" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Top CPU Processes:** $value - $details"
            break
        fi
    done

    # Process count - show once
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Process Activity" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Active Processes:** $value - $details"
            break
        fi
    done

    # Disk usage - show only the main volume, no directory clutter
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" =~ "Disk Usage: /System/Volumes/Data" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
            if [[ "$risk_level" == "MEDIUM" || "$risk_level" == "HIGH" ]]; then
                echo "- **Disk Space Warning:** $value - $details"
                if [[ -n "$recommendation" ]]; then
                    echo "  - Action: $recommendation"
                fi
            else
                echo "- **Disk Space:** $value - $details"
            fi
            break
        fi
    done

    echo ""
}

generate_network_interfaces() {
    cat << EOF
## Network Configuration

EOF

    # Network interface basics - no duplicates
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Active Interfaces" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Network Status:** $value - $details"
            break
        fi
    done

    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Primary IP Address" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **IP Address:** $value - $details"
            break
        fi
    done

    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "DNS Servers" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **DNS:** $value - $details"
            break
        fi
    done

    # VPN info if present
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "VPN Configuration" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **VPN:** $value - $details"
            break
        fi
    done

    echo ""
}

generate_security_management() {
    cat << EOF
## Security & Management

EOF

    # Authentication
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Login Management" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Authentication:** $value - $details"
            break
        fi
    done

    # MDM and management - consolidated
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "MDM Enrollment" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Device Management:** $value (MDM)"
            break
        fi
    done

    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Device Supervision" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Device Supervision:** $value"
            break
        fi
    done

    # Backup - fix the duplicate issue
    local backup_found=false
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Time Machine Backups" && "$backup_found" == false ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Backup (Time Machine):** $value - $details"
            if [[ -n "$recommendation" ]]; then
                echo "  - Action: $recommendation"
            fi
            backup_found=true
            break
        fi
    done

    echo ""
}

generate_security_analysis() {
    cat << EOF
## Security Analysis

EOF

    # High-risk ports - show once at top, no duplicates
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "High-Risk Listening Ports" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Risky Network Ports:** $value - $details"
            if [[ -n "$recommendation" ]]; then
                echo "  - Action: $recommendation"
            fi
            break
        fi
    done

    # Network services - combine listening services with actual port details
    local listening_count=""
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Listening Services" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            listening_count="$value"
            break
        fi
    done

    # Show specific ports found
    local port_details=""
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" =~ "Port " ]]; then
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            if [[ -n "$port_details" ]]; then
                port_details="$port_details, $details"
            else
                port_details="$details"
            fi
        fi
    done

    if [[ -n "$listening_count" ]]; then
        echo "- **Network Services:** $listening_count"
        if [[ -n "$port_details" ]]; then
            echo "  - Active: $port_details"
        fi
    fi

    # Remote access software
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Remote Access Software" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Remote Access Tools:** $value - $details"
            if [[ -n "$recommendation" ]]; then
                echo "  - Action: $recommendation"
            fi
            break
        fi
    done

    # Antivirus/Antimalware detection
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Third-party Antivirus" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Antivirus Protection:** $value - $details"
            break
        fi
    done

    # RMM/Remote Management Tools
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "RMM Tools" || "$item" == "Remote Management" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **RMM Tools:** $value - $details"
            if [[ -n "$recommendation" ]]; then
                echo "  - Action: $recommendation"
            fi
            break
        fi
    done

    # iCloud Status
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "iCloud Status" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **iCloud Status:** $value - $details"
            break
        fi
    done

    # Find My Status
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Find My" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Find My:** $value - $details"
            break
        fi
    done

    # WiFi security concerns
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Saved Wi-Fi Networks" && "$risk_level" == "LOW" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **WiFi Security:** $value saved networks"
            if [[ -n "$recommendation" ]]; then
                echo "  - Action: $recommendation"
            fi
            break
        fi
    done

    echo ""
}

generate_software_inventory() {
    cat << EOF
## Software Inventory

EOF

    # Application count
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Total Installed Applications" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Installed Applications:** $value - $details"
            break
        fi
    done

    # Key applications - show only the important ones
    local key_apps=("Zoom" "Microsoft Office" "Visual Studio Code" "Docker Desktop" "Safari Browser")
    for app in "${key_apps[@]}"; do
        for finding in "${ALL_FINDINGS[@]}"; do
            local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
            if [[ "$item" == "$app" ]]; then
                local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
                local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
                echo "- **$app:** $value"
                break
            fi
        done
    done

    # Development tools summary
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Development Tools" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Development Tools:** $value - $details"
            break
        fi
    done

    echo ""
}

# Old process section function removed - replaced by integrated system resources section

generate_memory_section() {
    cat << EOF
## Memory Analysis

EOF

    # Get memory-related findings
    local memory_items=("Memory Usage" "Top 5 Process Memory Usage" "Memory Pressure")

    for memory_item in "${memory_items[@]}"; do
        for finding in "${ALL_FINDINGS[@]}"; do
            local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
            local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)

            if [[ "$item" == "$memory_item" ]]; then
                local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
                local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
                local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)

                [[ -z "$value" ]] && value="Unknown"
                [[ -z "$risk_level" ]] && risk_level="INFO"

                local risk_icon="[INFO]"
                [[ "$risk_level" == "LOW" ]] && risk_icon="[LOW]"
                [[ "$risk_level" == "MEDIUM" ]] && risk_icon="[MEDIUM]"
                [[ "$risk_level" == "HIGH" ]] && risk_icon="[HIGH]"

                cat << EOF
- **$risk_icon $item:** $value
  - Details: $details
EOF
                if [[ -n "$recommendation" ]]; then
                    cat << EOF
  - Recommendation: $recommendation
EOF
                fi
                echo ""
                break
            fi
        done
    done
}

generate_disk_section() {
    cat << EOF
## Disk Analysis

EOF

    # Get disk-related findings - pattern match for disk usage items
    for finding in "${ALL_FINDINGS[@]}"; do
        local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)

        # Include Storage category and disk-related items, but exclude individual directory listings
        if [[ ("$category" == "Storage" || "$item" =~ "Disk") && ! "$item" =~ "Directory:" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)

            [[ -z "$value" ]] && value="Unknown"
            [[ -z "$risk_level" ]] && risk_level="INFO"

            local risk_icon="[INFO]"
            [[ "$risk_level" == "LOW" ]] && risk_icon="[LOW]"
            [[ "$risk_level" == "MEDIUM" ]] && risk_icon="[MEDIUM]"
            [[ "$risk_level" == "HIGH" ]] && risk_icon="[HIGH]"

            cat << EOF
- **$risk_icon $item:** $value
  - Details: $details
EOF
            if [[ -n "$recommendation" ]]; then
                cat << EOF
  - Recommendation: $recommendation
EOF
            fi
            echo ""
        fi
    done
}

generate_network_section() {
    cat << EOF
## Network Analysis

EOF

    # Get network-related findings
    local network_items=("High-Risk Listening Ports" "Active Interfaces" "Primary IP Address" "Wi-Fi Status" "Saved Wi-Fi Networks" "DNS Servers" "Listening Services" "Sharing Services" "VPN Configuration")

    for network_item in "${network_items[@]}"; do
        for finding in "${ALL_FINDINGS[@]}"; do
            local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
            local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)

            if [[ "$item" == "$network_item" ]]; then
                local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
                local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
                local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)

                [[ -z "$value" ]] && value="Unknown"
                [[ -z "$risk_level" ]] && risk_level="INFO"

                local risk_icon="[INFO]"
                [[ "$risk_level" == "LOW" ]] && risk_icon="[LOW]"
                [[ "$risk_level" == "MEDIUM" ]] && risk_icon="[MEDIUM]"
                [[ "$risk_level" == "HIGH" ]] && risk_icon="[HIGH]"

                cat << EOF
- **$risk_icon $item:** $value
  - Details: $details
EOF
                if [[ -n "$recommendation" ]]; then
                    cat << EOF
  - Recommendation: $recommendation
EOF
                fi
                echo ""
                break
            fi
        done
    done

    # Also include specific port findings that might not match the standard items
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)

        # Include port findings
        if [[ "$item" =~ "Port " && "$category" == "Network" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)

            [[ -z "$value" ]] && value="Unknown"
            [[ -z "$risk_level" ]] && risk_level="INFO"

            local risk_icon="[INFO]"
            [[ "$risk_level" == "LOW" ]] && risk_icon="[LOW]"
            [[ "$risk_level" == "MEDIUM" ]] && risk_icon="[MEDIUM]"
            [[ "$risk_level" == "HIGH" ]] && risk_icon="[HIGH]"

            cat << EOF
- **$risk_icon $item:** $value
  - Details: $details
EOF
            echo ""
        fi
    done
}

generate_recommendations() {
    # Collect only LOW risk recommendations that aren't already in Critical Action Items
    local recommendations=()
    local rec_counts=()

    # Skip only inappropriate recommendations - let the logic determine what to show based on actual status
    local skip_recommendations=(
        "1 network printers detected. Ensure they are on trusted networks and use secure protocols"
        "Evaluate enterprise security solutions such as CrowdStrike, SentinelOne, or Jamf Protect for comprehensive threat detection"
        "Review remote access software for security and business justification"
        "Time Machine is configured but no backups have completed. Verify backup destination is accessible"
        "Review listening services for security implications. Disable unnecessary services"
        "Disk space is getting low. Monitor usage and consider cleanup"
        "Backup solutions detected - verify they are configured and running properly"
        "Consider signing into iCloud for backup and device synchronization"
        "Sign into iCloud and enable backup for data protection"
        "Enable Find My for device security and theft protection"
        "Sign into iCloud to enable Find My"
    )

    for finding in "${ALL_FINDINGS[@]}"; do
        local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
        local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)

        if [[ -n "$recommendation" && "$recommendation" != "" && "$risk_level" == "LOW" ]]; then
            # Check if this recommendation should be skipped
            local should_skip=false
            for skip_rec in "${skip_recommendations[@]}"; do
                if [[ "$recommendation" == "$skip_rec" ]]; then
                    should_skip=true
                    break
                fi
            done

            if [[ "$should_skip" == false ]]; then
                # Check if this recommendation already exists
                local rec_exists=false
                local rec_index=0

                for i in "${!recommendations[@]}"; do
                    if [[ "${recommendations[$i]}" == "$recommendation" ]]; then
                        rec_exists=true
                        rec_index=$i
                        break
                    fi
                done

                if [[ "$rec_exists" == true ]]; then
                    # Increment count
                    rec_counts[$rec_index]=$((${rec_counts[$rec_index]} + 1))
                else
                    # Add new recommendation
                    recommendations+=("$recommendation")
                    rec_counts+=(1)
                fi
            fi
        fi
    done

    if [[ ${#recommendations[@]} -gt 0 ]]; then
        cat << EOF
## Additional Recommendations

EOF

        for i in "${!recommendations[@]}"; do
            cat << EOF
- **${recommendations[$i]}**

EOF
        done
    fi
}

generate_markdown_footer() {
    cat << EOF
---

*This report was generated by macOS Workstation Auditor v$CONFIG_VERSION*

*For detailed data analysis and aggregation, refer to the corresponding JSON export.*

EOF
}

# Main report export functions called by the main script
export_reports() {
    log_message "INFO" "Starting report generation..." "REPORT"

    # Collect findings once from all modules
    collect_all_findings

    # Generate both report formats using the same data
    export_markdown_report
    export_raw_data_json

    log_message "SUCCESS" "All reports generated successfully" "REPORT"
}