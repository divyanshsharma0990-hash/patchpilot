"""PatchPilot static content: playbooks, change-path guidance, wave names and FAQ.

Edit this file to change wording without touching the app logic.
"""

PLATFORMS = [
    "Windows",
    "Linux",
    "VMware ESXi / vCenter",
    "Network device",
    "Application / other",
]

WAVES = {1: "Emergency", 2: "This cycle", 3: "Next cycle", 4: "Backlog"}

REBOOT_HINT = {
    "Windows": "Usually yes",
    "Linux": "Kernel/glibc: yes. Others: service restart",
    "VMware ESXi / vCenter": "Host reboot (maintenance mode)",
    "Network device": "Usually (reload or failover)",
    "Application / other": "Service restart",
    "Unknown": "Check vendor advisory",
}

PATH_NOTES = {
    "Emergency": [
        "Raise an emergency change and attach the exploitation evidence (CISA KEV entry, vendor advisory).",
        "Patch within the P1 window. If you cannot, apply the vendor workaround or a compensating control right away and record a time-limited exception.",
        "Inform stakeholders and on-call teams, and watch logs and alerts for exploitation attempts until the fix is in.",
    ],
    "Normal": [
        "Add the fix to the next regular patch cycle for its priority.",
        "Test on a pilot or non-production group first.",
        "Use a standard change and confirm the maintenance window before you start.",
    ],
}

WORKFLOWS = {
    "Windows": {
        "pre": [
            "Confirm the KB or update applies to your OS build and check what it supersedes (MSRC Update Guide, Microsoft Update Catalog).",
            "Read the known issues for the update.",
            "Take a backup or VM snapshot, following your policy for domain controllers and databases.",
            "Check free disk space and make sure no reboot is already pending.",
            "Confirm the maintenance window and tell application owners.",
        ],
        "patch": [
            "Deploy through your patch tool (WSUS, SCCM/Intune or similar) to a pilot group first.",
            "Roll out to the remaining systems in waves.",
            "Reboot as required and keep the reboot order for clustered or dependent servers.",
        ],
        "validate": [
            "Confirm the KB is installed (update history or `Get-HotFix`).",
            "Check services, event logs and key applications.",
            "Rescan to confirm the vulnerability is gone (scanners may lag until their next scan).",
        ],
        "rollback": [
            "Uninstall the update (`wusa /uninstall /kb:<number>`) or restore the snapshot.",
            "If a business application breaks, stop the rollout, record an incident and re-plan with the vendor.",
        ],
    },
    "Linux": {
        "pre": [
            "Identify the distribution and the installed package version.",
            "Find the fixed package version in the distribution advisory (Red Hat RHSA, Ubuntu USN, Debian DSA/tracker).",
            "Take a snapshot or backup of the host and its config.",
            "Check whether the package is the kernel, glibc, OpenSSL or similar (reboot or many service restarts needed).",
            "Make sure the repository or mirror already carries the fixed package.",
        ],
        "patch": [
            "Update only the affected package (`dnf update <pkg>` or `apt install --only-upgrade <pkg>`), or run the full update if policy says so.",
            "Kernel updates: reboot into the new kernel, or use live patching if you have it.",
            "Restart dependent services (`needs-restarting -s` on RHEL family, `needrestart` on Debian/Ubuntu).",
        ],
        "validate": [
            "Check the package version (`rpm -q <pkg>` or `dpkg -l <pkg>`) and the running kernel (`uname -r`).",
            "Check service status and application health.",
            "Rescan to confirm the finding is closed.",
        ],
        "rollback": [
            "Downgrade the package or use `dnf history undo`.",
            "For kernels, boot the previous kernel from the boot menu.",
            "Restore the snapshot if needed.",
        ],
    },
    "VMware ESXi / vCenter": {
        "pre": [
            "Read the Broadcom/VMware advisory (VMSA) and note the fixed build number for ESXi and vCenter.",
            "Check hardware and interoperability compatibility for the target build.",
            "Back up vCenter (file-based backup) and export the host configuration.",
            "Check cluster capacity, DRS and HA so hosts can be emptied one at a time.",
            "Plan host order and the maintenance window.",
        ],
        "patch": [
            "Update vCenter first. It must be at or above the ESXi version.",
            "Then update hosts one at a time: enter maintenance mode, let VMs migrate, apply the patch or image, reboot, exit maintenance mode.",
            "Wait for the host to show healthy before starting the next one.",
        ],
        "validate": [
            "Confirm the ESXi and vCenter build numbers match the fixed build.",
            "Check host connection state, alarms, VM placement and cluster health.",
            "Rescan to confirm the finding is closed.",
        ],
        "rollback": [
            "ESXi keeps the previous image: roll back at boot (press Shift+R in the boot loader) and reapply the old image if needed.",
            "Restore vCenter from the file-based backup if the update fails.",
        ],
    },
    "Network device": {
        "pre": [
            "Read the vendor advisory for the fixed release and any workaround.",
            "Check that your model supports the fixed release and whether an intermediate upgrade is required.",
            "Back up the configuration and download the image, then verify its checksum.",
            "Identify HA pairs, the standby unit and the failover behaviour.",
            "Make sure console or out-of-band access works before the window starts.",
        ],
        "patch": [
            "HA pairs: upgrade the standby first, fail over, then upgrade the other unit (follow the vendor upgrade guide).",
            "Single devices: upgrade inside the window with console access ready.",
            "Reload and wait for the device to come back fully.",
        ],
        "validate": [
            "Confirm the running version.",
            "Check routing neighbours, VPN tunnels, interfaces and HA sync state.",
            "Check logs, then rescan to confirm the finding is closed.",
        ],
        "rollback": [
            "Boot the previous image and restore the saved configuration.",
            "Keep the old image on the device until validation is finished.",
        ],
    },
    "Application / other": {
        "pre": [
            "Find the vendor advisory and the fixed version.",
            "Back up the application, its configuration and its data.",
            "Test the update in non-production first.",
            "Check dependencies and plan for a service restart.",
        ],
        "patch": [
            "Apply the vendor update and restart the service.",
            "For libraries (Java, Log4j and similar), rebuild and redeploy every application that bundles them.",
        ],
        "validate": [
            "Confirm the version number.",
            "Run functional smoke tests.",
            "Rescan to confirm the finding is closed.",
        ],
        "rollback": [
            "Restore the backup or redeploy the previous version.",
        ],
    },
}

FAQ = [
    (
        "Priority",
        "What do P1 to P4 mean in PatchPilot?",
        "P1: actively exploited (listed in CISA KEV) or very likely to be exploited (EPSS 70% or higher). "
        "P2: critical severity (CVSS 9.0 or higher) or EPSS 30% or higher. "
        "P3: high severity (CVSS 7.0 or higher) or EPSS 10% or higher. "
        "P4: everything else. Marking a lookup or batch as internet-facing moves anything below P1 up one level. "
        "The patch windows are adjustable in Settings; align them with your organization's policy.",
    ),
    (
        "Priority",
        "Why patch an exploited 'medium' before an unexploited 'critical'?",
        "CVSS describes how severe a flaw is if it is exploited, not how likely that is. "
        "KEV and EPSS add real-world exploitation signals, so an exploited medium often carries more near-term risk.",
    ),
    (
        "Priority",
        "What are CISA KEV and EPSS?",
        "KEV is CISA's catalog of vulnerabilities known to be exploited in the wild, with remediation due dates for US federal agencies. "
        "Many teams use those dates as a benchmark. EPSS, from FIRST.org, estimates the probability that a CVE will be exploited in the next 30 days.",
    ),
    (
        "Patching basics",
        "Cumulative or security-only: which Windows update do I need?",
        "Current Windows releases ship cumulative updates, so the latest one includes earlier fixes. "
        "Check the update's page for any required servicing stack update and for what it supersedes, so you do not deploy older ones for no reason.",
    ),
    (
        "Patching basics",
        "Do I need to reboot after patching?",
        "Windows updates usually need a reboot. On Linux, kernel and core library updates need a reboot (or live patching), while other packages need only a service restart. "
        "ESXi hosts need a reboot, and network devices usually need a reload or failover. The vendor advisory is the final word.",
    ),
    (
        "Patching basics",
        "How do I confirm a patch was applied?",
        "Check the installed KB, package version or build number on the system, then rescan. "
        "A scanner can keep showing the finding until its next scan or until a reboot completes the install.",
    ),
    (
        "Safety and rollback",
        "What should I back up, and when should I roll back?",
        "Take a snapshot or backup of the system and its configuration (config export for network devices, vCenter backup for ESXi). "
        "Roll back when a critical service fails validation inside the window and cannot be fixed quickly, and record what happened.",
    ),
    (
        "Safety and rollback",
        "What if there is no patch yet, or I cannot patch?",
        "Apply the vendor workaround if there is one, and add compensating controls: restrict exposure, disable the affected feature, "
        "use WAF or IPS signatures, segment the system and increase monitoring. Record a time-limited exception with an owner and an expiry date.",
    ),
    (
        "Platform tips",
        "In what order do I patch VMware ESXi and vCenter?",
        "Update vCenter first, since it must be at or above the ESXi version. Then update hosts one at a time: maintenance mode, migrate VMs, patch, reboot, exit maintenance mode, and check health before the next host.",
    ),
    (
        "Platform tips",
        "How do I upgrade firewalls or routers in an HA pair?",
        "In general, upgrade the standby unit first, fail over, then upgrade the other unit. Back up the configuration and keep out-of-band access ready. "
        "Always follow the vendor's documented upgrade path for your model.",
    ),
    (
        "Using PatchPilot",
        "How does the Bulk bundler group findings?",
        "By the fix, not the CVE. A KB number in a title groups findings by that update. Otherwise the product (from the title, or from the CVE record) decides, "
        "so many CVEs that one update closes end up in one bundle. Bundles are ranked by highest priority, then by KEV count, then by number of CVEs closed.",
    ),
    (
        "Using PatchPilot",
        "My export has only QIDs or plugin IDs. What happens?",
        "A QID cannot be mapped to a CVE with public data. Rows that have a title PatchPilot recognises are still bundled (unscored, shown as P3). "
        "Rows it cannot place go to the unmapped list, which you can download, fill in the CVE column and upload again.",
    ),
    (
        "Using PatchPilot",
        "Where does the data come from, and how fresh is it?",
        "NVD, the CVE.org record, CISA KEV and FIRST EPSS. Results are cached for up to an hour. "
        "Fixed versions come from the CVE record when the vendor published them. If nothing is listed, use the vendor links on the result. "
        "Always confirm the fixed version in the vendor advisory before patching.",
    ),
    (
        "Patching basics",
        "Where can I download the patch without logging in?",
        "Microsoft: the Update Catalog needs no sign-in. PatchPilot links to the KB search when it can work out the KB number. "
        "A few vendors (Chrome, Firefox, Thunderbird, OpenSSL and others) have public download pages. "
        "Cisco, Palo Alto, Fortinet, F5, Juniper, VMware/Broadcom, Oracle and Citrix keep patch files behind a support-account login, "
        "so PatchPilot shows the advisory page instead. Linux fixes come through your distribution's package repositories.",
    ),
    (
        "Using PatchPilot",
        "Is my data stored?",
        "PatchPilot only needs CVE IDs, vulnerability titles or QIDs. Please do not upload hostnames, IP addresses or other internal data. "
        "Uploads are processed during your session and are not saved by the app. CVE IDs are sent to the public sources above to fetch details.",
    ),
    (
        "Using PatchPilot",
        "Can I rely on the checklists and change request drafts?",
        "They are general best practice to speed up your work. Adjust them to your organization's change process, SLAs and vendor guidance.",
    ),
]
