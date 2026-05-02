const FRAMEWORKS = {
  OWASP_SAMM: {
    id: "OWASP-SAMM",
    name: "OWASP Software Assurance Maturity Model",
    note: "Alignment mapping only. This is not a formal certification claim."
  },
  CIS_CONTROLS: {
    id: "CIS-Controls-v8",
    name: "CIS Critical Security Controls v8",
    note: "Alignment mapping only. This is not a formal certification claim."
  }
};

const CONTROLS = {
  DNS_RESOLUTION: {
    owaspSamm: [
      {
        function: "Verification",
        practice: "Security Testing",
        reason: "Confirms the target can be resolved before security verification."
      },
      {
        function: "Operations",
        practice: "Incident Management",
        reason: "DNS failure can affect availability and operational response."
      }
    ],
    cisControls: [
      {
        control: "CIS Control 12",
        title: "Network Infrastructure Management",
        reason: "DNS reachability is part of external service exposure visibility."
      }
    ]
  },
  HTTPS_REQUIRED: {
    owaspSamm: [
      {
        function: "Verification",
        practice: "Security Testing",
        reason: "Validates encrypted transport for web application traffic."
      },
      {
        function: "Implementation",
        practice: "Secure Build",
        reason: "Transport security must be enforced in deployment configuration."
      }
    ],
    cisControls: [
      {
        control: "CIS Control 4",
        title: "Secure Configuration of Enterprise Assets and Software",
        reason: "HTTPS enforcement is a secure service configuration baseline."
      },
      {
        control: "CIS Control 16",
        title: "Application Software Security",
        reason: "Web applications should protect data in transit."
      }
    ]
  },
  TLS_CERTIFICATE: {
    owaspSamm: [
      {
        function: "Verification",
        practice: "Security Testing",
        reason: "Checks certificate trust and lifecycle for transport protection."
      },
      {
        function: "Operations",
        practice: "Operational Management",
        reason: "Certificate expiry and trust issues are operational security risks."
      }
    ],
    cisControls: [
      {
        control: "CIS Control 4",
        title: "Secure Configuration of Enterprise Assets and Software",
        reason: "TLS certificate configuration must remain valid and trusted."
      }
    ]
  },
  HTTPS_REDIRECT: {
    owaspSamm: [
      {
        function: "Verification",
        practice: "Security Testing",
        reason: "Verifies insecure HTTP requests are upgraded to HTTPS."
      }
    ],
    cisControls: [
      {
        control: "CIS Control 4",
        title: "Secure Configuration of Enterprise Assets and Software",
        reason: "Redirecting HTTP to HTTPS reduces insecure service exposure."
      }
    ]
  },
  SECURITY_HEADERS: {
    owaspSamm: [
      {
        function: "Verification",
        practice: "Security Testing",
        reason: "Security headers are testable web application hardening controls."
      },
      {
        function: "Implementation",
        practice: "Secure Build",
        reason: "Headers should be configured as part of secure deployment."
      }
    ],
    cisControls: [
      {
        control: "CIS Control 4",
        title: "Secure Configuration of Enterprise Assets and Software",
        reason: "Security headers are secure configuration safeguards for web software."
      },
      {
        control: "CIS Control 16",
        title: "Application Software Security",
        reason: "Headers reduce common web application attack impact."
      }
    ]
  },
  HTTP_AVAILABILITY: {
    owaspSamm: [
      {
        function: "Operations",
        practice: "Incident Management",
        reason: "Unreachable web services should be visible to security operations."
      }
    ],
    cisControls: [
      {
        control: "CIS Control 8",
        title: "Audit Log Management",
        reason: "Availability failures should be recorded for review and response."
      }
    ]
  },
  SECURITY_MONITORING: {
    owaspSamm: [
      {
        function: "Operations",
        practice: "Incident Management",
        reason: "Security events support detection, triage, and response workflows."
      }
    ],
    cisControls: [
      {
        control: "CIS Control 8",
        title: "Audit Log Management",
        reason: "Security events should be collected and reviewed."
      },
      {
        control: "CIS Control 16",
        title: "Application Software Security",
        reason: "Application activity monitoring supports attack detection."
      }
    ]
  }
};

const getStandards = (controlId) => {
  const control = CONTROLS[controlId];

  if (!control) {
    throw new Error(`Unknown security standards control: ${controlId}`);
  }

  return {
    frameworkMode: "alignedWith",
    frameworks: FRAMEWORKS,
    mappings: control
  };
};

const buildStandardsSummary = (controlIds) => ({
  frameworkMode: "alignedWith",
  note: "These mappings show design alignment with OWASP SAMM and CIS Controls. They do not represent formal compliance certification.",
  frameworks: FRAMEWORKS,
  controlsCovered: [...new Set(controlIds)]
});

module.exports = {
  CONTROLS,
  FRAMEWORKS,
  buildStandardsSummary,
  getStandards
};
