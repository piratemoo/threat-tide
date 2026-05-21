(() => {
  const root = document.getElementById("pm-vulns-app");
  if (!root || root.dataset.ready === "true") return;
  root.dataset.ready = "true";

  const LIVE_FEED_URL = "https://raw.githubusercontent.com/piratemoo/vuln-feed/refs/heads/main/vulns.json";
  const HERO_IMAGE_URL = "https://raw.githubusercontent.com/piratemoo/vuln-feed/refs/heads/main/yespls.png";
  let liveFeedUpdatedAt = "";

  const severityIcons = {
    critical: "https://raw.githubusercontent.com/piratemoo/vuln-feed/refs/heads/main/1.png",
    high: "https://raw.githubusercontent.com/piratemoo/vuln-feed/refs/heads/main/2.png",
    medium: "https://raw.githubusercontent.com/piratemoo/vuln-feed/refs/heads/main/3.png"
  };

  const MAX_LINKS_PER_CARD = 8;
  const MAX_TAGS_PER_CARD = 8;

  const menuItems = [
    { label: "All", section: "all" },
    { label: "Windows", section: "windows" },
    { label: "Linux", section: "linux" },
    { label: "Mobile", section: "mobile", children: [
      { label: "Android", section: "android" },
      { label: "iOS", section: "ios" }
    ] },
    { label: "Research", section: "research" }
  ];

  const sourcePool = [
    { name: "CISA KEV", lane: "observed exploitation", url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", weight: 100 },
    { name: "FIRST EPSS", lane: "probability enrichment", url: "https://api.first.org/data/v1/epss", weight: 82 },
    { name: "NVD CVE API", lane: "baseline CVE metadata", url: "https://services.nvd.nist.gov/rest/json/cves/2.0", weight: 55 },
    { name: "GitHub Advisory DB", lane: "advisory metadata", url: "https://github.com/advisories", weight: 62 },
    { name: "GitHub poc search", lane: "candidate pocs", url: "https://api.github.com/search/repositories", weight: 45 },
    { name: "Google Security Blog", lane: "mobile/platform research", url: "https://blog.google/security/", weight: 92 },
    { name: "Project Zero", lane: "original research", url: "https://projectzero.google/", weight: 96 },
    { name: "P0 0-days ITW", lane: "in-the-wild history", url: "https://googleprojectzero.github.io/0days-in-the-wild/", weight: 94 },
    { name: "chompie", lane: "kernel exploit dev", url: "https://x.com/chompie1337", weight: 94 },
    { name: "Maddie Stone", lane: "0-day exploit analysis", url: "https://x.com/maddiestone", weight: 92 },
    { name: "Natalie Silvanovich", lane: "mobile/browser research", url: "https://x.com/natashenka", weight: 91 },
    { name: "Google TAG", lane: "0-day threat intel", url: "https://blog.google/threat-analysis-group/", weight: 90 },
    { name: "watchTowr Labs", lane: "weaponizable research", url: "https://labs.watchtowr.com/", weight: 94 },
    { name: "Horizon3 Attack Team", lane: "exploit validation", url: "https://horizon3.ai/attack-research/", weight: 90 },
    { name: "_dirkjan", lane: "AD, Entra, Kerberos", url: "https://dirkjanm.io/", weight: 94 },
    { name: "SSD Disclosure", lane: "original disclosure", url: "https://ssd-disclosure.com/", weight: 86 },
    { name: "Synacktiv", lane: "exploit research", url: "https://www.synacktiv.com/en/publications.html", weight: 88 },
    { name: "SpecterOps", lane: "identity attack paths", url: "https://specterops.io/blog/", weight: 92 },
    { name: "Orange Tsai", lane: "web and appliance chains", url: "https://blog.orange.tw/", weight: 94 },
    { name: "ZDI Blog", lane: "research writeups", url: "https://www.zerodayinitiative.com/blog", weight: 88 },
    { name: "ZDI Advisories", lane: "coordinated disclosures", url: "https://www.zerodayinitiative.com/advisories/", weight: 80 },
    { name: "NCC Group Research", lane: "technical research", url: "https://research.nccgroup.com/", weight: 86 },
    { name: "Elastic Security Labs", lane: "threat research", url: "https://www.elastic.co/security-labs", weight: 78 },
    { name: "Kaspersky GReAT", lane: "mobile exploit research", url: "https://securelist.com/", weight: 86 },
    { name: "Exodus Intelligence", lane: "exploit research", url: "https://blog.exodusintel.com/", weight: 82 },
    { name: "Bishop Fox", lane: "operator research", url: "https://bishopfox.com/blog", weight: 82 },
    { name: "Assetnote", lane: "edge and web research", url: "https://www.assetnote.io/resources/research", weight: 88 },
    { name: "SonarSource", lane: "code-level research", url: "https://www.sonarsource.com/blog/", weight: 80 },
    { name: "Wiz Research", lane: "cloud research", url: "https://www.wiz.io/blog", weight: 82 },
    { name: "Aqua Nautilus", lane: "containers and cloud", url: "https://www.aquasec.com/blog/", weight: 78 },
    { name: "ProjectDiscovery", lane: "exposure tooling", url: "https://projectdiscovery.io/blog", weight: 72 },
    { name: "Metasploit", lane: "public tooling", url: "https://github.com/rapid7/metasploit-framework", weight: 78 },
    { name: "Exploit-DB", lane: "candidate pocs", url: "https://www.exploit-db.com/", weight: 42 },
    { name: "Packet Storm", lane: "candidate pocs", url: "https://packetstormsecurity.com/files/tags/exploit/", weight: 38 },
    { name: "Microsoft MSRC", lane: "Windows advisories", url: "https://msrc.microsoft.com/update-guide", weight: 78 },
    { name: "Android Bulletins", lane: "mobile advisories", url: "https://source.android.com/docs/security/bulletin", weight: 74 },
    { name: "Apple Security", lane: "iOS/macOS advisories", url: "https://support.apple.com/en-us/100100", weight: 74 },
    { name: "Chromium Security", lane: "browser advisories", url: "https://chromereleases.googleblog.com/", weight: 72 },
    { name: "VMware Advisories", lane: "virtualization", url: "https://support.broadcom.com/web/ecx/security-advisory", weight: 76 },
    { name: "Citrix Bulletins", lane: "edge appliances", url: "https://support.citrix.com/securitybulletins", weight: 76 },
    { name: "Fortinet PSIRT", lane: "edge appliances", url: "https://www.fortiguard.com/psirt", weight: 76 },
    { name: "Palo Alto Advisories", lane: "edge appliances", url: "https://security.paloaltonetworks.com/", weight: 78 },
    { name: "Cisco PSIRT", lane: "network edge", url: "https://sec.cloudapps.cisco.com/security/center/publicationListing.x", weight: 74 },
    { name: "Ivanti Security", lane: "enterprise edge", url: "https://forums.ivanti.com/s/security-advisories", weight: 76 },
    { name: "GitLab Releases", lane: "dev platform", url: "https://about.gitlab.com/releases/categories/releases/", weight: 70 },
    { name: "GitHub Security Lab", lane: "research and advisories", url: "https://github.blog/security/vulnerability-research/", weight: 76 },
    { name: "Rapid7 AttackerKB", lane: "exploitability discussion", url: "https://attackerkb.com/", weight: 62 },
    { name: "The Shadowserver Foundation", lane: "internet exposure", url: "https://dashboard.shadowserver.org/", weight: 66 }
  ];

  root.innerHTML = `
    <div class="pm-wrap">
      <main class="pm-main">
        <section class="pm-panel pm-hero-image" aria-label="Threat Tide social art">
          <img src="${HERO_IMAGE_URL}" alt="Threat Tide daily vuln feed" loading="eager" decoding="async">
        </section>

        <section class="pm-panel pm-tide-header" aria-label="Threat Tide status">
          <div class="pm-tide-stats" aria-label="Feed status">
            <span><strong data-pm-date>Today</strong></span>
            <span class="pm-check-cell"><span class="pm-last-check-label">Last Check:</span> <span data-pm-last-check>--</span></span>
            <span><strong>verified</strong> public pocs <b class="pm-count-inline" data-pm-count>0</b> posted today</span>
          </div>
        </section>

        <section class="pm-panel pm-source-pool" aria-label="Tracked source pool">
          <button class="pm-source-toggle" type="button" aria-expanded="false" aria-controls="pm-source-list">
            <span>Source pool</span>
            <strong><span data-pm-source-count>0</span> tracked</strong>
          </button>
          <div class="pm-source-list" id="pm-source-list" aria-hidden="true"></div>
        </section>

        <nav class="pm-panel pm-menu" aria-label="Vulnerability sections"></nav>

        <section class="pm-panel pm-filters" aria-label="Filter vulnerabilities">
          <input data-filter="query" placeholder="Search CVE, vulnerability, paper, researcher" aria-label="Search vulnerabilities">
          <select data-filter="severity" aria-label="Severity">
            <option value="all">All severity</option>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
          </select>
          <input data-filter="tag" placeholder="tag" aria-label="Filter by tag">
        </section>

        <section class="pm-feed" aria-label="Curated vulnerabilities"></section>

        <section class="pm-panel pm-archive" aria-label="Archived daily feeds">
          <div class="pm-archive-head">
            <span>Archived feeds</span>
            <strong>7 days</strong>
          </div>
          <div class="pm-archive-days"></div>
        </section>
      </main>
    </div>
  `;

  const state = { section: "all", query: "", severity: "all", tag: "", day: 0 };
  const fallbackVulns = [
    {
      cve: "CVE-2024-4577",
      title: "PHP-CGI argument injection with public watchTowr exploit",
      ecosystem: "cloud",
      category: "webstack",
      severity: "critical",
      proof: "working public poc",
      reliability: "reliable exploit",
      researcher: "watchTowr Labs",
      researcherUrl: "https://x.com/watchtowrcyber",
      pocWorks: "Yes",
      added: "tracked",
      language: "Python",
      summary: "PHP-CGI argument injection on affected Windows locale deployments gives a practical remote code execution path with a public researcher poc.",
      breakdown: "The useful signal is not the CVSS number; it is the narrow but very real deployment pattern. Hunt for PHP-CGI behind Apache/XAMPP-style stacks, especially externally reachable Windows hosts using affected locales or equivalent argument parsing exposure.",
      whatBroke: "PHP-CGI argument handling could be coerced through Windows character conversion behavior, turning request parameters into interpreter switches.",
      reality: "Realistic against the right PHP-CGI deployment shape. The public watchTowr poc is a useful validator, but broad scanning still needs environment checks.",
      chains: "Initial web RCE, webshell placement, credential collection, lateral movement from legacy Windows web hosts, and follow-on identity abuse.",
      weaponized: "Likely and already attractive because the bug sits on internet-facing web stacks and has a clean public exploit path.",
      tags: ["Cloud", "Webstack", "RCE", "KEV"],
      confidence: 94,
      weaponization: 96,
      dayOffset: 0,
      links: [
        ["GitHub", "https://github.com/watchtowrlabs/CVE-2024-4577"],
        ["Technical Paper", "https://labs.watchtowr.com/no-way-php-strikes-again-cve-2024-4577/"],
        ["Vendor Advisory", "https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv"]
      ]
    },
    {
      cve: "NO-CVE",
      title: "AD CS template abuse remains chainable identity infrastructure debt",
      ecosystem: "windows",
      category: "adcs",
      severity: "high",
      proof: "working public poc",
      reliability: "reliable exploit",
      researcher: "@SpecterOps",
      researcherUrl: "https://x.com/SpecterOps",
      pocWorks: "Yes",
      added: "watch",
      language: "Python / C#",
      summary: "Misconfigured certificate templates and enrollment paths continue to turn ordinary domain access into durable identity escalation opportunities.",
      breakdown: "Track template enrollment rights, manager approval bypasses, ESC-style paths, NTLM relay to certificate endpoints, and whether recent hardening changed exploit reliability in the target estate.",
      whatBroke: "Certificate trust and enrollment policy can permit authentication material issuance beyond intended privilege boundaries.",
      reality: "Highly realistic where templates, web enrollment, or relay conditions line up. This is configuration-driven, not patch-only.",
      chains: "NTLM relay, coercion, Kerberos abuse, low-priv domain footholds, and persistence through certificate lifetime.",
      weaponized: "Already operationalized in mature tooling. The variable is target configuration, not exploit state.",
      tags: ["Windows", "ADCS", "Privilege Escalation"],
      confidence: 92,
      weaponization: 88,
      dayOffset: 0,
      links: [
        ["GitHub", "https://github.com/GhostPack/Certify"],
        ["Technical Paper", "https://specterops.io/blog/2021/06/17/certified-pre-owned/"]
      ]
    },
    {
      cve: "CVE-2024-1086",
      title: "Linux nf_tables UAF LPE with public repro chain",
      ecosystem: "linux",
      category: "kernel",
      severity: "medium",
      proof: "working public poc",
      reliability: "partial exploit",
      researcher: "@Notselwyn",
      researcherUrl: "https://github.com/Notselwyn",
      pocWorks: "Yes",
      added: "tracked",
      language: "C",
      summary: "nf_tables use-after-free research remains useful for local privilege escalation triage on affected Linux kernels with public exploit code available.",
      breakdown: "The operational value is kernel exposure mapping, namespace/container preconditions, and whether the target fleet carries vulnerable kernel lines. Treat pocs as environment-sensitive but worth validating in lab images that mirror production.",
      whatBroke: "A kernel memory lifetime bug in nf_tables can permit local code to shape a privilege escalation primitive.",
      reality: "Realistic where affected kernels and required local execution conditions line up. The exploit path is public, but reliability depends on kernel build and mitigations.",
      chains: "Initial foothold, container escape research, local privilege escalation, and persistence setup after low-priv execution.",
      weaponized: "Likely in targeted post-exploitation workflows. Less useful as a drive-by issue, valuable once an operator already has code execution.",
      tags: ["Linux", "Kernel", "Local LPE"],
      confidence: 88,
      weaponization: 72,
      dayOffset: 0,
      links: [
        ["GitHub", "https://github.com/Notselwyn/CVE-2024-1086"],
        ["Technical Paper", "https://pwning.tech/nftables/"]
      ]
    },
    {
      cve: "CVE-2024-0044",
      title: "Android run-as package installer forgery with public bypass poc",
      ecosystem: "android",
      category: "framework",
      severity: "high",
      proof: "working public poc",
      reliability: "reliable exploit",
      researcher: "Meta RTX / canyie",
      researcherUrl: "https://github.com/canyie",
      pocWorks: "Yes",
      added: "tracked",
      language: "Shell / Java",
      summary: "Android PackageInstaller input validation can be abused from an adb foothold to run code as another installed app, which makes it useful for app-data access and device-lab privilege testing.",
      breakdown: "This is not remote initial access, but it is useful mobile tradecraft once an operator has adb, local debugging access, or a chained device foothold. The real value is crossing app UID boundaries and validating whether fleet devices carry the vulnerable framework behavior.",
      whatBroke: "PackageInstaller session creation accepted crafted input that crossed into the downstream run-as path and confused which app identity should be used.",
      reality: "Realistic under local/adb preconditions. The public bypass poc is repeatable for validation on affected Android builds.",
      chains: "ADB access, malicious local app workflow, app data access, token theft from targeted apps, and follow-on mobile persistence testing.",
      weaponized: "Likely as a post-access mobile primitive. It is not broad remote exploitation, but it is practical in device labs and chained workflows.",
      tags: ["Android", "Framework", "Local LPE"],
      confidence: 86,
      weaponization: 68,
      dayOffset: 0,
      links: [
        ["GitHub", "https://github.com/canyie/CVE-2024-0044"],
        ["Technical Paper", "https://rtx.meta.security/exploitation/2024/03/04/Android-run-as-forgery.html"],
        ["Vendor Advisory", "https://source.android.com/security/bulletin/2024-03-01"]
      ]
    },
    {
      cve: "CVE-2023-32434",
      title: "iOS kfd kernel r/w primitive with public exploit library",
      ecosystem: "ios",
      category: "kernel",
      severity: "high",
      proof: "working public poc",
      reliability: "partial exploit",
      researcher: "Kaspersky GReAT / kfd",
      researcherUrl: "https://securelist.com/",
      pocWorks: "Yes",
      added: "tracked",
      language: "C / Objective-C",
      summary: "Public kfd-style exploit code provides kernel memory access primitives on supported iOS versions, with value depending heavily on device model, build, and exploit method.",
      breakdown: "This belongs in mobile triage because iOS kernel primitives are chain material, not because they are universally push-button. Track supported device/version ranges, installation preconditions, and whether a public primitive can pair with CoreTrust, WebKit, or sandbox escape work.",
      whatBroke: "An Apple kernel integer overflow path could be shaped into kernel privilege code execution or kernel memory read/write under the right conditions.",
      reality: "Realistic in supported lab/device conditions. Reliability is version-specific and should be validated against exact hardware and iOS builds.",
      chains: "WebKit or app foothold, sandbox escape, kernel r/w primitive, CoreTrust-style signing bypass, jailbreak tooling, and mobile implant research.",
      weaponized: "Likely in high-end chains, but public tooling is mostly useful for research, validation, and jailbreak-adjacent workflows.",
      tags: ["iOS", "Kernel", "Local LPE"],
      confidence: 84,
      weaponization: 66,
      dayOffset: 0,
      links: [
        ["GitHub", "https://github.com/GeoSn0w/kfd-exploit"],
        ["Technical Paper", "https://securelist.com/operation-triangulation-the-last-hardware-mystery/111669/"],
        ["Vendor Advisory", "https://support.apple.com/en-us/HT213808"]
      ]
    },
    {
      cve: "CVE-2024-27198",
      title: "TeamCity auth bypass to CI server code execution",
      ecosystem: "cloud",
      category: "devops",
      severity: "critical",
      proof: "working public poc",
      reliability: "reliable exploit",
      researcher: "Rapid7",
      researcherUrl: "https://www.rapid7.com/blog/",
      pocWorks: "Yes",
      added: "1d ago",
      language: "Python",
      summary: "JetBrains TeamCity authentication bypass remains operator-relevant because CI servers often sit near secrets, deployment keys, and build trust.",
      breakdown: "The exploit path is valuable because the target is not just an app server; it is a software supply-chain control point. Prioritize exposed TeamCity, forgotten agents, and credential material available to build runners.",
      whatBroke: "A request path allowed authentication bypass against TeamCity administrative surfaces.",
      reality: "Realistic where exposed instances lag patching. Public exploit code and scanner checks make validation straightforward.",
      chains: "CI secrets theft, build pipeline compromise, package tampering, cloud credential reuse, and lateral movement through deployment automation.",
      weaponized: "Likely. CI products convert initial access into broad environment leverage quickly.",
      tags: ["Cloud", "DevOps", "RCE"],
      confidence: 90,
      weaponization: 86,
      dayOffset: 1,
      links: [
        ["Tooling", "https://github.com/rapid7/metasploit-framework"],
        ["Technical Paper", "https://www.rapid7.com/blog/post/2024/03/04/etr-cve-2024-27198-and-cve-2024-27199-jetbrains-teamcity-multiple-authentication-bypass-vulnerabilities/"],
        ["Vendor Advisory", "https://blog.jetbrains.com/teamcity/2024/03/additional-critical-security-issues-affecting-teamcity-on-premises-cve-2024-27198-and-cve-2024-27199-update-to-2023-11-4-now/"]
      ]
    },
    {
      cve: "CVE-2024-1709",
      title: "ScreenConnect authentication bypass with instant fleet value",
      ecosystem: "windows",
      category: "rmm",
      severity: "critical",
      proof: "working public poc",
      reliability: "reliable exploit",
      researcher: "ConnectWise / Huntress",
      researcherUrl: "https://www.huntress.com/blog",
      pocWorks: "Yes",
      added: "1d ago",
      language: "Python / HTTP",
      summary: "ScreenConnect auth bypass is high-signal because RMM compromise often means privileged access across many downstream machines.",
      breakdown: "Operator value is in blast radius: remote management tools collapse many endpoints into one control plane. Prioritize internet exposure, unknown admin creation, and historical persistence left by opportunistic exploitation.",
      whatBroke: "A setup/authentication flow could be abused to gain administrative control without valid credentials.",
      reality: "Very realistic on exposed and unpatched appliances. public pocs made opportunistic validation trivial.",
      chains: "RMM control, endpoint command execution, credential theft, lateral movement, and MSP-style downstream compromise.",
      weaponized: "Already weaponized in broad scanning and intrusion workflows.",
      tags: ["Windows", "RMM", "Auth Bypass"],
      confidence: 93,
      weaponization: 94,
      dayOffset: 1,
      links: [
        ["Tooling", "https://github.com/rapid7/metasploit-framework"],
        ["Technical Paper", "https://www.huntress.com/blog/a-catastrophe-for-control-understanding-the-screenconnect-authentication-bypass"],
        ["Vendor Advisory", "https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8"]
      ]
    },
    {
      cve: "CVE-2024-23897",
      title: "Jenkins CLI file read that chains into controller compromise",
      ecosystem: "linux",
      category: "webstack",
      severity: "high",
      proof: "working public poc",
      reliability: "partial exploit",
      researcher: "SonarSource",
      researcherUrl: "https://www.sonarsource.com/blog/",
      pocWorks: "Yes",
      added: "2d ago",
      language: "Java / Python",
      summary: "Jenkins arbitrary file read is useful when it exposes secrets, crumb issuers, credentials, or plugin state that can be chained into execution.",
      breakdown: "Treat this as a chain primitive rather than a one-shot RCE. The interesting question is what sensitive files are readable in the target controller context and whether those secrets unlock job execution or admin paths.",
      whatBroke: "Jenkins CLI argument expansion allowed unauthorized file content disclosure from the controller.",
      reality: "Realistic as an information disclosure and chain step. Exploit quality depends on target hardening and reachable secrets.",
      chains: "Credential recovery, Jenkins admin takeover, build job execution, SCM token theft, and cloud deployment key abuse.",
      weaponized: "Likely as a chaining primitive. It is especially valuable on CI systems with broad secrets.",
      tags: ["Linux", "DevOps", "File Read"],
      confidence: 86,
      weaponization: 78,
      dayOffset: 2,
      links: [
        ["GitHub", "https://github.com/jenkinsci-cert/SECURITY-3314-3315"],
        ["Technical Paper", "https://www.sonarsource.com/blog/excessive-expansion-uncovering-critical-security-vulnerabilities-in-jenkins/"],
        ["Vendor Advisory", "https://www.jenkins.io/security/advisory/2024-01-24/"]
      ]
    },
    {
      cve: "CVE-2023-4966",
      title: "Citrix Bleed session theft with durable edge-access value",
      ecosystem: "cloud",
      category: "vpn-edge",
      severity: "critical",
      proof: "working public poc",
      reliability: "reliable exploit",
      researcher: "Assetnote",
      researcherUrl: "https://www.assetnote.io/resources/research",
      pocWorks: "Yes",
      added: "2d ago",
      language: "Python",
      summary: "Citrix ADC/Gateway session disclosure stays relevant because stolen sessions can bypass normal credential and MFA assumptions.",
      breakdown: "This is an access primitive. Look for historic compromise, active sessions created before patching, persistence after appliance remediation, and whether session theft fed downstream identity abuse.",
      whatBroke: "A memory disclosure issue exposed sensitive session material from Citrix ADC/Gateway.",
      reality: "Realistic against affected edge appliances. public pocs made validation and theft workflows accessible.",
      chains: "Session hijack, VPN access, internal discovery, credential collection, and identity pivoting.",
      weaponized: "Already observed and operationally valuable because it bypasses password-centric thinking.",
      tags: ["Cloud", "VPN Edge", "Session Theft", "KEV"],
      confidence: 94,
      weaponization: 95,
      dayOffset: 2,
      links: [
        ["GitHub", "https://github.com/assetnote/exploits"],
        ["Technical Paper", "https://www.assetnote.io/resources/research/citrix-bleed-leaking-session-tokens-with-cve-2023-4966"],
        ["Vendor Advisory", "https://support.citrix.com/article/CTX579459"]
      ]
    },
    {
      cve: "CVE-2024-6387",
      title: "OpenSSH regreSSHion as high-friction but important RCE research",
      ecosystem: "linux",
      category: "ssh",
      severity: "high",
      proof: "working public poc",
      reliability: "partial exploit",
      researcher: "Qualys TRU",
      researcherUrl: "https://www.qualys.com/research/security-labs/",
      pocWorks: "Yes",
      added: "3d ago",
      language: "C",
      summary: "OpenSSH signal-handler race research matters because SSH exposure is universal, even when exploitation is timing-sensitive and target-dependent.",
      breakdown: "This belongs in the archive because it is not easy-button exploitation, but the blast radius and service ubiquity are too important to ignore. Track exploit improvements, target architecture reliability, and distro-specific exposure.",
      whatBroke: "A regression reintroduced an unsafe signal-handler race condition in sshd.",
      reality: "Realistic in lab and select environments; difficult at scale without target-specific reliability work.",
      chains: "Internet SSH exposure, unauthenticated foothold attempts, post-exploit privilege context, and infrastructure-wide scanning.",
      weaponized: "Possible when reliability improves. Treat current public pocs as validation signals, not guaranteed commodity exploitation.",
      tags: ["Linux", "SSH", "RCE"],
      confidence: 82,
      weaponization: 64,
      dayOffset: 3,
      links: [
        ["Technical Paper", "https://www.qualys.com/regresshion-cve-2024-6387/"],
        ["Vendor Advisory", "https://www.openssh.com/txt/release-9.8"]
      ]
    },
    {
      cve: "CVE-2024-21762",
      title: "FortiOS SSL-VPN RCE on exposed perimeter appliances",
      ecosystem: "cloud",
      category: "vpn-edge",
      severity: "critical",
      proof: "working public poc",
      reliability: "partial exploit",
      researcher: "Fortinet PSIRT",
      researcherUrl: "https://www.fortiguard.com/psirt",
      pocWorks: "Yes",
      added: "3d ago",
      language: "Python",
      summary: "FortiOS SSL-VPN bugs stay high priority because exposed VPN appliances create direct edge-to-internal pivot opportunities.",
      breakdown: "Focus on version exposure, SSL-VPN enablement, appliance logs, and whether public exploit variants are converging into reliable checks versus noisy crashers.",
      whatBroke: "A FortiOS SSL-VPN vulnerability could permit code execution under specific appliance conditions.",
      reality: "Realistic for vulnerable exposed appliances, but poc reliability varies by build and target condition.",
      chains: "Perimeter RCE, credential harvesting, VPN trust abuse, internal discovery, and persistence on network edge.",
      weaponized: "Likely when reliable exploit variants are available. Edge appliance bugs are routinely folded into operator workflows.",
      tags: ["Cloud", "VPN Edge", "RCE"],
      confidence: 84,
      weaponization: 82,
      dayOffset: 3,
      links: [
        ["Vendor Advisory", "https://www.fortiguard.com/psirt/FG-IR-24-015"]
      ]
    },
    {
      cve: "CVE-2023-3519",
      title: "Citrix ADC unauthenticated RCE with proven intrusion history",
      ecosystem: "cloud",
      category: "vpn-edge",
      severity: "critical",
      proof: "working public poc",
      reliability: "reliable exploit",
      researcher: "Citrix / Assetnote",
      researcherUrl: "https://www.assetnote.io/resources/research",
      pocWorks: "Yes",
      added: "4d ago",
      language: "Python",
      summary: "Unauthenticated Citrix ADC/Gateway RCE remains archetypal edge-device risk: exploitable perimeter code with immediate internal-access implications.",
      breakdown: "Archive value is in exploit archaeology and historical compromise review. Even patched estates need incident review for webshells, appliance persistence, and stolen credentials.",
      whatBroke: "Citrix ADC/Gateway exposed an unauthenticated path to code execution on vulnerable appliances.",
      reality: "Highly realistic on affected exposed systems. The vulnerability has public exploit paths and strong historical exploitation signal.",
      chains: "Perimeter foothold, webshell, credential theft, internal pivoting, and appliance persistence.",
      weaponized: "Already weaponized; the main question is lingering compromise, not exploit possibility.",
      tags: ["Cloud", "VPN Edge", "RCE", "KEV"],
      confidence: 95,
      weaponization: 96,
      dayOffset: 4,
      links: [
        ["Tooling", "https://github.com/rapid7/metasploit-framework"],
        ["Technical Paper", "https://www.assetnote.io/resources/research/analysis-of-cve-2023-3519-in-citrix-adc-and-gateway"],
        ["Vendor Advisory", "https://support.citrix.com/article/CTX561482"]
      ]
    },
    {
      cve: "CVE-2024-0204",
      title: "GoAnywhere auth bypass with file-transfer blast radius",
      ecosystem: "cloud",
      category: "webstack",
      severity: "high",
      proof: "working public poc",
      reliability: "reliable exploit",
      researcher: "Fortra",
      researcherUrl: "https://www.fortra.com/security/advisories",
      pocWorks: "Yes",
      added: "4d ago",
      language: "Python / HTTP",
      summary: "Managed file transfer bugs deserve archive space because they often sit near sensitive data flows and partner trust boundaries.",
      breakdown: "Treat this as data-access and control-plane risk. Public exploitability matters less than what the application stores, transfers, and authenticates to downstream.",
      whatBroke: "An authentication bypass condition exposed administrative or sensitive application paths.",
      reality: "Realistic against vulnerable deployments. public pocs make validation straightforward.",
      chains: "Data theft, credential recovery, partner trust abuse, scheduled transfer tampering, and follow-on webshell or admin actions.",
      weaponized: "Likely in data theft operations due to the target class.",
      tags: ["Cloud", "File Transfer", "Auth Bypass"],
      confidence: 82,
      weaponization: 78,
      dayOffset: 4,
      links: [
        ["Vendor Advisory", "https://www.fortra.com/security/advisories/product-security/fi-2024-001"]
      ]
    },
    {
      cve: "CVE-2023-22518",
      title: "Confluence data-center takeover path with public exploit flow",
      ecosystem: "linux",
      category: "webstack",
      severity: "critical",
      proof: "working public poc",
      reliability: "reliable exploit",
      researcher: "Atlassian",
      researcherUrl: "https://confluence.atlassian.com/security/",
      pocWorks: "Yes",
      added: "5d ago",
      language: "Python / HTTP",
      summary: "Confluence remains a high-signal target when public exploit flows lead to administrative control or content-backed credential exposure.",
      breakdown: "Prioritize exposed Confluence, backup/restore behavior, app links, stored credentials, and marketplace plugin blast radius.",
      whatBroke: "A vulnerable Confluence path enabled improper control of instance state and administrative outcomes.",
      reality: "Realistic on exposed vulnerable instances. Public exploit automation exists and is easy to validate.",
      chains: "Admin takeover, user directory access, stored secrets, plugin deployment, and internal documentation mining.",
      weaponized: "Likely and historically common due to Confluence's enterprise footprint.",
      tags: ["Linux", "Webstack", "Auth Bypass"],
      confidence: 88,
      weaponization: 86,
      dayOffset: 5,
      links: [
        ["Tooling", "https://github.com/rapid7/metasploit-framework"],
        ["Vendor Advisory", "https://confluence.atlassian.com/security/cve-2023-22518-improper-authorization-vulnerability-in-confluence-data-center-and-server-1311473907.html"]
      ]
    },
    {
      cve: "CVE-2023-34362",
      title: "MOVEit Transfer SQLi-to-RCE exploitation archeology",
      ecosystem: "windows",
      category: "webstack",
      severity: "critical",
      proof: "working public poc",
      reliability: "reliable exploit",
      researcher: "Progress / Huntress",
      researcherUrl: "https://www.huntress.com/blog",
      pocWorks: "Yes",
      added: "5d ago",
      language: "Python / SQL",
      summary: "MOVEit remains a useful archive anchor for file-transfer exploitation, data theft workflows, and web app compromise at enterprise scale.",
      breakdown: "Track this as exploit archaeology: the target class, webshell deployment pattern, and data-theft motivation matter more than just the CVE mechanics.",
      whatBroke: "SQL injection in MOVEit Transfer enabled unauthorized access and paths toward code execution or data extraction.",
      reality: "Realistic against vulnerable exposed systems. Public exploit workflows are mature.",
      chains: "SQLi, webshell, file inventory, bulk exfiltration, credential reuse, and extortion operations.",
      weaponized: "Already weaponized and historically exploited at scale.",
      tags: ["Windows", "File Transfer", "SQLi", "KEV"],
      confidence: 94,
      weaponization: 95,
      dayOffset: 5,
      links: [
        ["Tooling", "https://github.com/rapid7/metasploit-framework"],
        ["Technical Paper", "https://www.huntress.com/blog/moveit-transfer-critical-vulnerability-rapid-response"],
        ["Vendor Advisory", "https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31May2023"]
      ]
    }
  ];

  let vulns = fallbackVulns.map(normalizeVuln);

  function numberOr(value, fallback) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : fallback;
  }

  function formatCentralTime(value) {
    if (!value) return "";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "";
    return new Intl.DateTimeFormat("en-US", {
      hour: "numeric",
      minute: "2-digit",
      timeZone: "America/Chicago",
      timeZoneName: "short"
    }).format(date);
  }

  function cleanAdded(value, fallbackTime) {
    const raw = cleanInlineText(value, 48);
    const directTime = formatCentralTime(raw);
    if (directTime) return directTime;
    const fallback = formatCentralTime(fallbackTime);
    if (fallback && (!raw || ["tracked", "watch", "queued"].includes(raw.toLowerCase()))) return fallback;
    return raw || fallback || "pending";
  }

  function cleanLanguage(value) {
    const raw = cleanInlineText(value, 64);
    if (!raw || raw.toLowerCase() === "unknown" || raw.toLowerCase() === "public tooling") return "Unknown";
    return titleCase(raw);
  }

  function titleCase(value) {
    return String(value || "")
      .split(/(\s+|\/|-)/)
      .map((part) => /[a-z]/i.test(part) ? part.charAt(0).toUpperCase() + part.slice(1) : part)
      .join("");
  }

  function difficultyFor(item) {
    if (item.difficulty) return titleCase(item.difficulty);
    const reliability = String(item.reliability || "").toLowerCase();
    const severity = String(item.severity || "").toLowerCase();
    const weaponization = numberOr(item.weaponization || item.weaponizationLikelihood, 0);
    if (reliability.includes("reliable") && (severity === "critical" || weaponization >= 85)) return "Easy";
    if (reliability.includes("reliable")) return "Moderate";
    if (reliability.includes("partial") || reliability.includes("lab")) return "Situational";
    return "Needs Validation";
  }

  function normalizeLinks(links) {
    if (!Array.isArray(links)) return [];
    return links
      .map((link) => {
        if (Array.isArray(link)) return [cleanInlineText(link[0] || "Reference", 48), safeUrl(link[1])];
        if (link && typeof link === "object") return [cleanInlineText(link.label || link.name || "Reference", 48), safeUrl(link.url)];
        return null;
      })
      .filter((link) => link && link[0] && link[1])
      .slice(0, MAX_LINKS_PER_CARD);
  }

  function normalizeVuln(item) {
    const rawTags = Array.isArray(item.tags) ? item.tags : [];
    const tags = rawTags.map((tag) => cleanInlineText(tag, 32)).filter(Boolean).slice(0, MAX_TAGS_PER_CARD);
    const tagEcosystem = tags.map((tag) => tag.toLowerCase()).find((tag) => ["windows", "linux", "android", "ios", "cloud"].includes(tag));
    const ecosystem = cleanSlug(item.ecosystem || tagEcosystem || "research", "research");
    const severity = cleanSlug(item.severity || "high", "high");
    const chainValue = Array.isArray(item.chains)
      ? item.chains.map((chain) => cleanInlineText(chain, 160)).filter(Boolean).slice(0, 8)
      : cleanBlockText(item.chains || "Use as a chain primitive with initial access, credential access, lateral movement, or persistence.", 500);
    return {
      cve: cleanInlineText(item.cve || "NO-CVE", 64),
      title: cleanInlineText(item.title || "Untitled vulnerability signal", 180),
      ecosystem,
      category: cleanSlug(item.category || "research", "research"),
      severity: ["critical", "high", "medium"].includes(severity) ? severity : "high",
      proof: cleanInlineText(item.proof || "working public poc", 80),
      reliability: cleanInlineText(item.reliability || "reliable exploit", 80),
      researcher: cleanInlineText(item.researcher || "unknown", 80),
      researcherUrl: safeUrl(item.researcherUrl),
      pocWorks: cleanInlineText(item.pocWorks || "Yes", 16),
      difficulty: cleanInlineText(difficultyFor(item), 32),
      added: cleanAdded(item.firstSeenAt || item.added, liveFeedUpdatedAt),
      language: cleanLanguage(item.language),
      summary: cleanBlockText(item.summary || "", 520),
      technicalSummary: cleanBlockText(item.technicalSummary || "", 520),
      breakdown: cleanBlockText(item.breakdown || item.summary || "", 800),
      exploitSyntax: cleanCodeText(item.exploitSyntax || "", 1200),
      whatBroke: cleanBlockText(item.whatBroke || "The affected component exposed a useful exploit primitive.", 500),
      reality: cleanBlockText(item.reality || "Realistic exploitation depends on exposure, version, and environmental preconditions.", 500),
      chains: chainValue,
      weaponized: cleanBlockText(item.weaponized || "Track public tooling and reproduction reports before treating it as broadly weaponized.", 500),
      tags,
      confidence: Math.max(0, Math.min(100, numberOr(item.confidence, 75))),
      weaponization: Math.max(0, Math.min(100, numberOr(item.weaponization || item.weaponizationLikelihood, 70))),
      dayOffset: Math.max(0, Math.min(6, numberOr(item.dayOffset, 0))),
      links: normalizeLinks(item.links)
    };
  }

  async function loadLiveFeed() {
    try {
      const response = await fetch(`${LIVE_FEED_URL}?t=${Date.now()}`, { cache: "no-store" });
      if (!response.ok) throw new Error(`feed ${response.status}`);
      const payload = await response.json();
      const items = Array.isArray(payload) ? payload : (Array.isArray(payload.vulns) ? payload.vulns : payload.items);
      if (!Array.isArray(items) || !items.length) throw new Error("empty feed");
      liveFeedUpdatedAt = payload && !Array.isArray(payload) ? String(payload.updatedAt || "") : "";
      vulns = items.map(normalizeVuln).filter((item) => item.cve && item.title);
      if (!vulns.length) throw new Error("empty normalized feed");
      root.dataset.feedSource = "github";
    } catch (error) {
      vulns = fallbackVulns.map(normalizeVuln);
      root.dataset.feedSource = "fallback";
    }
  }

  const tagIcons = {
    adcs: '<svg viewBox="0 0 24 24"><path d="M7 3h10v4h3v14H4V7h3V3Zm2 4h6V5H9v2Zm-3 2v10h12V9H6Zm3 3h6v2H9v-2Zm0 4h4v2H9v-2Z"/></svg>',
    android: '<svg viewBox="0 0 24 24"><path d="M8.2 6.2 6.4 3.4 7.9 2.5 9.8 5.4a8.2 8.2 0 0 1 4.4 0l1.9-2.9 1.5.9-1.8 2.8A7 7 0 0 1 19 12v7H5v-7a7 7 0 0 1 3.2-5.8ZM7 17h10v-5a5 5 0 0 0-10 0v5Zm3-6h2v2h-2v-2Zm4 0h2v2h-2v-2Z"/></svg>',
    cloud: '<svg viewBox="0 0 24 24"><path d="M8 19a5 5 0 0 1-.8-9.94A6.5 6.5 0 0 1 19.63 11H20a4 4 0 0 1 0 8H8Zm0-2h12a2 2 0 0 0 0-4h-1.92l-.24-.92A4.5 4.5 0 0 0 9.1 10.9l-.22.96-.98.06A3 3 0 0 0 8 17Z"/></svg>',
    "auth bypass": '<svg viewBox="0 0 24 24"><path d="M17 8V7a5 5 0 0 0-9.58-2H10a3 3 0 0 1 5 2v1h2Zm-9 3h12v9H8v-9Zm2 2v5h8v-5h-8ZM3 11h3v2H3v-2Zm0 4h3v2H3v-2Zm0-8h3v2H3V7Z"/></svg>',
    devops: '<svg viewBox="0 0 24 24"><path d="M7 7a5 5 0 0 1 8.7-3.35L18 5.95V3h2v7h-7V8h3.6l-2.32-2.32A3 3 0 1 0 12 10h1v2h-1a5 5 0 0 1-5-5Zm5 5h1a5 5 0 1 1-3.7 8.35L7 18.05V21H5v-7h7v2H8.4l2.32 2.32A3 3 0 1 0 13 14h-1v-2Z"/></svg>',
    "file read": '<svg viewBox="0 0 24 24"><path d="M6 2h9l5 5v15H6V2Zm8 2H8v16h10V8h-4V4Zm-3 7h4v2h-4v-2Zm0 4h4v2h-4v-2Z"/></svg>',
    "file transfer": '<svg viewBox="0 0 24 24"><path d="M4 5h10l2 2h4v12H4V5Zm2 4v8h12V9H6Zm5 1h2v3h3l-4 4-4-4h3v-3Z"/></svg>',
    framework: '<svg viewBox="0 0 24 24"><path d="M5 4h14v4H5V4Zm2 2v0h10V6H7Zm-2 5h6v9H5v-9Zm2 2v5h2v-5H7Zm6-2h6v9h-6v-9Zm2 2v5h2v-5h-2Z"/></svg>',
    high: '<svg viewBox="0 0 24 24"><path d="m12 3 10 18H2L12 3Zm0 5.1L5.4 19h13.2L12 8.1Zm-1 3.9h2v4h-2v-4Zm0 5h2v2h-2v-2Z"/></svg>',
    ios: '<svg viewBox="0 0 24 24"><path d="M8 2h8a2 2 0 0 1 2 2v16a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2Zm0 3v14h8V5H8Zm3 15h2v1h-2v-1Z"/></svg>',
    kev: '<svg viewBox="0 0 24 24"><path d="M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5l-8-3Zm0 2.2 6 2.25V11c0 3.9-2.4 7.55-6 8.85C8.4 18.55 6 14.9 6 11V6.45l6-2.25Zm3.7 5.1 1.4 1.4-6.1 6.1-3.6-3.6 1.4-1.4 2.2 2.2 4.7-4.7Z"/></svg>',
    kernel: '<svg viewBox="0 0 24 24"><path d="M8 3h2v3h4V3h2v3h2v2h3v2h-3v4h3v2h-3v2h-2v3h-2v-3h-4v3H8v-3H6v-2H3v-2h3v-4H3V8h3V6h2V3Zm0 5v8h8V8H8Zm2 2h4v4h-4v-4Z"/></svg>',
    linux: '<svg viewBox="0 0 24 24"><path d="M4 5h16v14H4V5Zm2 2v10h12V7H6Zm2.2 2 3 3-3 3-1.4-1.4L8.4 12 6.8 10.4 8.2 9Zm4.3 5H17v2h-4.5v-2Z"/></svg>',
    "local lpe": '<svg viewBox="0 0 24 24"><path d="M11 19V8.8l-4.6 4.6L5 12l7-7 7 7-1.4 1.4L13 8.8V19h-2Z"/></svg>',
    medium: '<svg viewBox="0 0 24 24"><path d="M4 11h16v2H4v-2Z"/></svg>',
    "privilege escalation": '<svg viewBox="0 0 24 24"><path d="M14 3a7 7 0 0 0-6.32 10.02L3 17.7V21h3.3l1-1H10v-2.7l1.02-1.02A7 7 0 1 0 14 3Zm0 2a5 5 0 1 1-2.55 9.3l-.66-.4L8 16.7V18H6.5l-1 1H5v-.5l5.1-5.08-.4-.66A5 5 0 0 1 14 5Zm2 2a2 2 0 1 1 0 4 2 2 0 0 1 0-4Z"/></svg>',
    rce: '<svg viewBox="0 0 24 24"><path d="M4 5h16v14H4V5Zm2 2v10h12V7H6Zm2 2 3 3-3 3-1.4-1.4L8.2 12l-1.6-1.6L8 9Zm4 5h4v2h-4v-2Z"/></svg>',
    rmm: '<svg viewBox="0 0 24 24"><path d="M3 4h18v12H3V4Zm2 2v8h14V6H5Zm4 12h6l1 2H8l1-2Zm1-10h4v2h-4V8Zm5 0h2v2h-2V8Z"/></svg>',
    "session theft": '<svg viewBox="0 0 24 24"><path d="M12 2a5 5 0 0 1 5 5v2h2v13H5V9h2V7a5 5 0 0 1 5-5Zm0 2a3 3 0 0 0-3 3v2h6V7a3 3 0 0 0-3-3Zm-5 7v9h10v-9H7Zm4 2h2v4h-2v-4Z"/></svg>',
    sqli: '<svg viewBox="0 0 24 24"><path d="M12 3c4.4 0 8 1.34 8 3v12c0 1.66-3.6 3-8 3s-8-1.34-8-3V6c0-1.66 3.6-3 8-3Zm0 2c-3.54 0-5.7.88-6 1 .3.12 2.46 1 6 1s5.7-.88 6-1c-.3-.12-2.46-1-6-1ZM6 9v2c.94.58 3.08 1 6 1s5.06-.42 6-1V9c-1.48.62-3.58 1-6 1S7.48 9.62 6 9Zm0 5v2c.94.58 3.08 1 6 1s5.06-.42 6-1v-2c-1.48.62-3.58 1-6 1s-4.52-.38-6-1Z"/></svg>',
    ssh: '<svg viewBox="0 0 24 24"><path d="M7 10V7a5 5 0 0 1 10 0v3h2v11H5V10h2Zm2 0h6V7a3 3 0 0 0-6 0v3Zm-2 2v7h10v-7H7Z"/></svg>',
    webstack: '<svg viewBox="0 0 24 24"><path d="M4 5h16v14H4V5Zm2 4h12V7H6v2Zm0 2v6h12v-6H6Zm2 1.5h3V14H8v-1.5Zm0 2.5h8v1.5H8V15Z"/></svg>',
    windows: '<svg viewBox="0 0 24 24"><path d="M3 5.5 11 4v7H3V5.5Zm10-1.88 8-1.5V11h-8V3.62ZM3 13h8v7l-8-1.5V13Zm10 0h8v8.88l-8-1.5V13Z"/></svg>'
  };

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"})[char]);
  }

  function cleanInlineText(value, maxLength = 240) {
    return String(value || "")
      .replace(/[\u0000-\u001F\u007F]/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, maxLength);
  }

  function cleanBlockText(value, maxLength = 800) {
    return String(value || "")
      .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, " ")
      .replace(/[ \t]+/g, " ")
      .replace(/\n{3,}/g, "\n\n")
      .trim()
      .slice(0, maxLength);
  }

  function cleanCodeText(value, maxLength = 1200) {
    return String(value || "")
      .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, " ")
      .trim()
      .slice(0, maxLength);
  }

  function cleanSlug(value, fallback) {
    const slug = String(value || "")
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, "-")
      .replace(/-+/g, "-")
      .replace(/^-|-$/g, "");
    return slug || fallback;
  }

  function safeUrl(value) {
    const raw = String(value || "").trim();
    if (!raw) return "";
    try {
      const url = new URL(raw, window.location.origin);
      if (!["https:", "http:"].includes(url.protocol)) return "";
      if (url.username || url.password) return "";
      return url.href;
    } catch (error) {
      return "";
    }
  }

  function safeHref(value) {
    return escapeHtml(safeUrl(value) || "#");
  }

  function safeExternalAttrs() {
    return 'target="_blank" rel="noopener noreferrer"';
  }

  function archiveDate(dayOffset) {
    const date = new Date();
    date.setDate(date.getDate() - dayOffset);
    return date;
  }

  function archiveLabel(dayOffset) {
    if (dayOffset === 0) return "Today";
    if (dayOffset === 1) return "Yesterday";
    return new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric" }).format(archiveDate(dayOffset));
  }

  function sectionMatches(item) {
    const tags = item.tags.map((tag) => tag.toLowerCase());
    return state.section === "all"
      || item.ecosystem === state.section
      || (state.section === "mobile" && (item.ecosystem === "android" || item.ecosystem === "ios"))
      || (state.section === "research" && item.links.some(([label]) => label.toLowerCase().includes("technical") || label.toLowerCase().includes("writeup")));
  }

  function filteredItems() {
    const query = state.query.trim().toLowerCase();
    const tag = state.tag.trim().toLowerCase();
    return vulns.filter((item) => {
      const haystack = [item.cve, item.title, item.ecosystem, item.category, item.summary, item.proof, item.reliability, item.researcher, item.language, ...item.tags].join(" ").toLowerCase();
      return sectionMatches(item)
        && ((item.dayOffset || 0) === state.day)
        && (state.severity === "all" || item.severity === state.severity)
        && (!query || haystack.includes(query))
        && (!tag || item.tags.some((itemTag) => itemTag.toLowerCase().includes(tag)));
    });
  }

  function renderSourcePool() {
    const count = root.querySelector("[data-pm-source-count]");
    const list = root.querySelector(".pm-source-list");
    if (count) count.textContent = String(sourcePool.length);
    if (!list) return;
    list.innerHTML = sourcePool
      .slice()
      .sort((left, right) => right.weight - left.weight)
      .map((source) => `
        <a class="pm-source-chip" href="${safeHref(source.url)}" ${safeExternalAttrs()}>
          <strong>${escapeHtml(source.name)}</strong>
          <span>${escapeHtml(source.lane)}</span>
        </a>`)
      .join("");
  }

  function renderArchive() {
    const archive = root.querySelector(".pm-archive-days");
    if (!archive) return;
    archive.innerHTML = Array.from({ length: 7 }, (_, dayOffset) => {
      const count = vulns.filter((item) => (item.dayOffset || 0) === dayOffset).length;
      const pressed = state.day === dayOffset ? "true" : "false";
      return `<button type="button" class="pm-archive-day" data-day="${dayOffset}" aria-pressed="${pressed}">
        <span>${archiveLabel(dayOffset)}</span>
        <strong>${count}</strong>
      </button>`;
    }).join("");
    archive.querySelectorAll("[data-day]").forEach((button) => {
      button.addEventListener("click", () => {
        state.day = Number(button.dataset.day);
        render();
      });
    });
  }

  function isActive(section) {
    if (section === "mobile") return ["mobile", "android", "ios"].includes(state.section);
    return state.section === section;
  }

  function menuButton(item, extraClass = "") {
    return `<button type="button" class="pm-menu-button ${extraClass}" data-section="${item.section}" aria-pressed="${isActive(item.section)}">${item.label}</button>`;
  }

  function renderMenu() {
    root.querySelector(".pm-menu").innerHTML = menuItems.map((item) => {
      if (!item.children) return menuButton(item);
      const children = item.children.map((child) => menuButton(child)).join("");
      return `<div class="pm-menu-group">${menuButton(item, "pm-has-submenu")}<div class="pm-submenu">${children}</div></div>`;
    }).join("");
    root.querySelectorAll("[data-section]").forEach((button) => {
      button.addEventListener("click", () => {
        state.section = button.dataset.section;
        render();
      });
    });
  }

  function actionLinks(item) {
    return item.links.map(([label, url]) => `<a href="${safeHref(url)}" ${safeExternalAttrs()}>${escapeHtml(label)}</a>`).join("");
  }

  const platformIcons = {
    x: '<svg viewBox="0 0 24 24"><path d="M17.7 3h3.1l-6.9 7.9L22 21h-6.4l-5-6.2L5 21H2l7.4-8.5L1.6 3h6.5l4.5 5.7L17.7 3Zm-1.1 16.2h1.7L7.2 4.7H5.4l11.2 14.5Z"/></svg>',
    github: '<svg viewBox="0 0 24 24"><path d="M12 2a10 10 0 0 0-3.2 19.5c.5.1.7-.2.7-.5v-1.8c-2.9.6-3.5-1.2-3.5-1.2-.5-1.1-1.1-1.4-1.1-1.4-.9-.6.1-.6.1-.6 1 0 1.6 1.1 1.6 1.1.9 1.6 2.4 1.1 3 .9.1-.7.4-1.1.7-1.4-2.3-.3-4.7-1.1-4.7-5A3.9 3.9 0 0 1 6.6 9c-.1-.3-.4-1.3.1-2.7 0 0 .8-.3 2.8 1a9.5 9.5 0 0 1 5 0c1.9-1.3 2.8-1 2.8-1 .5 1.4.2 2.4.1 2.7a3.9 3.9 0 0 1 1 2.7c0 3.9-2.4 4.8-4.7 5 .4.3.7 1 .7 2v2.3c0 .3.2.6.8.5A10 10 0 0 0 12 2Z"/></svg>',
    web: '<svg viewBox="0 0 24 24"><path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm6.9 9h-3.1a15.6 15.6 0 0 0-1.2-5 8.1 8.1 0 0 1 4.3 5ZM12 4.1c.7 1 1.4 2.9 1.7 4.9h-3.4c.3-2 .9-3.9 1.7-4.9ZM4.3 13h3.9c.1 1.8.5 3.5 1.1 4.9A8 8 0 0 1 4.3 13Zm3.9-2H4.3a8 8 0 0 1 5-4.9A15 15 0 0 0 8.2 11Zm3.8 8.9c-.8-1-1.4-2.8-1.7-4.9h3.4c-.3 2.1-1 3.9-1.7 4.9Zm2.1-6.9H9.9a16 16 0 0 1 0-2h4.2a16 16 0 0 1 0 2Zm.6 4.9c.6-1.4 1-3.1 1.1-4.9h3.9a8 8 0 0 1-5 4.9Z"/></svg>'
  };

  function platformIcon(url) {
    const lower = String(url || "").toLowerCase();
    if (lower.includes("x.com/") || lower.includes("twitter.com/")) return platformIcons.x;
    if (lower.includes("github.com/")) return platformIcons.github;
    return platformIcons.web;
  }

  function tagPill(tag) {
    const icon = tagIcons[tag.toLowerCase()];
    const iconHtml = icon ? `<span class="pm-tag-icon" aria-hidden="true">${icon}</span>` : "";
    return `<span class="pm-tag">${iconHtml}${escapeHtml(tag)}</span>`;
  }

  function researcherLink(item) {
    if (!item.researcherUrl) return `<span class="meta-value">${escapeHtml(item.researcher)}</span>`;
    return `<a class="meta-value meta-link" href="${safeHref(item.researcherUrl)}" ${safeExternalAttrs()}><span class="pm-researcher-icon" aria-hidden="true">${platformIcon(item.researcherUrl)}</span><span>${escapeHtml(item.researcher)}</span></a>`;
  }

  function repoUrl(item) {
    const match = item.links.find(([label, url]) => {
      const lowerLabel = String(label).toLowerCase();
      return lowerLabel.includes("github") || lowerLabel.includes("tooling") || String(url).includes("github.com/");
    });
    return match ? match[1] : "";
  }

  function repoName(url) {
    try {
      const path = new URL(url).pathname.split("/").filter(Boolean);
      return path[1] || "poc";
    } catch (error) {
      return "poc";
    }
  }

  function exploitSyntax(item) {
    if (item.exploitSyntax) return item.exploitSyntax;
    const url = repoUrl(item);
    const name = repoName(url);
    const language = String(item.language || "").toLowerCase();
    const lines = [
      "# authorized lab / owned targets only",
      url ? `git clone ${url}` : "# open the linked GitHub/tooling reference",
      `cd ${name}`
    ];
    if (language.includes("python")) {
      lines.push("python3 <script>.py --target https://<authorized-target>");
    } else if (language === "go" || language.includes("golang")) {
      lines.push("go run . --target https://<authorized-target>");
    } else if (["c", "c++", "cpp"].includes(language)) {
      lines.push("make", "./<compiled-poc> <authorized-target>");
    } else if (language.includes("ruby")) {
      lines.push("ruby <script>.rb --target https://<authorized-target>");
    } else if (language.includes("java")) {
      lines.push("java -jar <poc>.jar https://<authorized-target>");
    } else if (language.includes("shell") || language.includes("bash")) {
      lines.push("bash <script>.sh https://<authorized-target>");
    } else {
      lines.push("# use the repo README invocation against https://<authorized-target>");
    }
    lines.push("# confirm exact flags in the linked GitHub README before validation");
    return lines.join("\n");
  }

  function technicalSummary(item) {
    const category = String(item.category || "").toLowerCase();
    const tags = item.tags.map((tag) => String(tag).toLowerCase());
    if (category === "webstack" && tags.includes("auth bypass")) {
      return "Authentication checks happen too late or are skipped on a privileged path. A crafted request can reach control-plane behavior without a valid session.";
    }
    if (category === "webstack" && tags.includes("rce")) {
      return "A web-exposed parser or handler accepts attacker-shaped input and passes it into execution logic. The bug turns request data into server-side code or command behavior.";
    }
    if (category === "vpn-edge" || tags.includes("vpn edge")) {
      return "A perimeter appliance exposes logic that should only run after stronger validation. The root issue is unauthenticated or weakly authenticated input reaching trusted edge-device internals.";
    }
    if (category === "adcs" || tags.includes("adcs")) {
      return "Certificate enrollment or relay rules allow identity material to be issued outside the intended trust boundary. The abuse path converts weak domain access into stronger authentication.";
    }
    if (category === "devops") {
      return "A CI or automation control plane exposes sensitive behavior through a routing, auth, or file-access mistake. The core risk is access to build secrets, jobs, runners, or deployment credentials.";
    }
    if (category === "kernel" || tags.includes("kernel")) {
      return "Kernel state or memory lifetime is mishandled in a reachable code path. Exploitation depends on shaping that primitive into elevated control from local execution.";
    }
    if (item.technicalSummary) {
      const cleaned = item.technicalSummary
        .replace(/^Technical Paper signal:\s*/i, "")
        .replace(/^[^:]{2,32} writeup:\s*/i, "")
        .replace(/\bThe practical signal is that\b.*$/i, "")
        .replace(/\bThe updater only includes this\b.*$/i, "")
        .trim();
      if (cleaned && cleaned.toLowerCase() !== String(item.summary || "").toLowerCase()) return compactSummary(cleaned);
    }
    if (item.whatBroke) return compactSummary(item.whatBroke);
    return "Attacker-controlled input crosses a trust boundary the product handles incorrectly. The public code is useful because it validates that vulnerable path directly.";
  }

  function compactSummary(value) {
    const text = String(value || "").replace(/\s+/g, " ").trim();
    if (text.length <= 210) return text;
    return `${text.slice(0, 207).replace(/\s+\S*$/, "")}.`;
  }

  function relatedResources(item) {
    const resources = [];
    const add = (label, url) => {
      if (!url || resources.some((resource) => resource.url === url)) return;
      resources.push({ label, url });
    };
    const category = String(item.category || "").toLowerCase();
    const ecosystem = String(item.ecosystem || "").toLowerCase();
    const tags = item.tags.map((tag) => String(tag).toLowerCase());
    if (category === "adcs" || tags.includes("adcs")) {
      add("AD CS ESC abuse", "https://specterops.io/blog/2021/06/17/certified-pre-owned/");
      add("Certifried CVE-2022-26923", "https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4");
      add("PetitPotam relay chain", "https://github.com/topotam/PetitPotam");
    }
    if (category === "vpn-edge") {
      add("Citrix Bleed CVE-2023-4966", "https://www.assetnote.io/resources/research/citrix-bleed-leaking-session-tokens-with-cve-2023-4966");
      add("Citrix ADC CVE-2023-3519", "https://www.assetnote.io/resources/research/analysis-of-cve-2023-3519-in-citrix-adc-and-gateway");
      add("FortiOS CVE-2024-21762", "https://www.fortiguard.com/psirt/FG-IR-24-015");
    }
    if (category === "webstack") {
      add("PHP-CGI CVE-2024-4577", "https://labs.watchtowr.com/no-way-php-strikes-again-cve-2024-4577/");
      add("Confluence CVE-2023-22518", "https://confluence.atlassian.com/security/cve-2023-22518-improper-authorization-vulnerability-in-confluence-data-center-and-server-1311473907.html");
      add("GeoServer CVE-2024-36401", "https://geoserver.org/vulnerability/2024/09/12/cve-2024-36401.html");
    }
    if (category === "devops") {
      add("Jenkins CVE-2024-23897", "https://www.sonarsource.com/blog/excessive-expansion-uncovering-critical-security-vulnerabilities-in-jenkins/");
      add("TeamCity CVE-2024-27198", "https://www.rapid7.com/blog/post/2024/03/04/etr-cve-2024-27198-and-cve-2024-27199-jetbrains-teamcity-multiple-authentication-bypass-vulnerabilities/");
      add("GitLab CVE-2023-7028", "https://about.gitlab.com/releases/2024/01/11/critical-security-release-gitlab-16-7-2-released/");
    }
    if (category === "kernel" || ecosystem === "linux") {
      add("nf_tables CVE-2024-1086", "https://pwning.tech/nftables/");
      add("regreSSHion CVE-2024-6387", "https://www.qualys.com/regresshion-cve-2024-6387/");
      add("Dirty Pipe CVE-2022-0847", "https://dirtypipe.cm4all.com/");
    }
    if (ecosystem === "android") {
      add("Android run-as CVE-2024-0044", "https://rtx.meta.security/exploitation/2024/03/04/Android-run-as-forgery.html");
      add("Android StrandHogg CVE-2020-0096", "https://source.android.com/docs/security/bulletin/2020-05-01");
      add("Android Framework bulletins", "https://source.android.com/docs/security/bulletin");
    }
    if (ecosystem === "ios") {
      add("iOS kernel CVE-2023-32434", "https://support.apple.com/en-us/HT213808");
      add("Operation Triangulation", "https://securelist.com/operation-triangulation-the-last-hardware-mystery/111669/");
      add("Project Zero ITW iOS bugs", "https://googleprojectzero.github.io/0days-in-the-wild/");
    }
    if (!resources.length) {
      add("Recent exploited CVEs", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
      add("Exploitability discussion", "https://attackerkb.com/");
    }
    return resources.slice(0, 5);
  }

  function difficultyClass(value) {
    const lower = String(value || "").toLowerCase();
    if (lower.includes("easy")) return "pm-difficulty-easy";
    if (lower.includes("moderate")) return "pm-difficulty-moderate";
    if (lower.includes("situational")) return "pm-difficulty-situational";
    return "pm-difficulty-validation";
  }

  function card(item, index) {
    const detailId = `pm-vuln-detail-${index}`;
    const severity = item.severity.toLowerCase();
    const tags = item.tags.map(tagPill).join("");
    const researcher = researcherLink(item);
    const difficulty = item.difficulty || difficultyFor(item);
    return `
      <article class="pm-panel pm-card">
        <div class="severity-column">
          <img src="${severityIcons[severity] || severityIcons.medium}" alt="${escapeHtml(item.severity)} severity cow icon">
          <p class="severity-label pm-${severity}-text">${escapeHtml(item.severity)}</p>
        </div>
        <div class="pm-card-main">
          <div class="pm-cve-row"><span class="pm-cve pm-mono">${escapeHtml(item.cve)}</span>${tags}</div>
          <h2>${escapeHtml(item.title)}</h2>
          <p class="pm-summary">${escapeHtml(item.summary)}</p>
          <div class="pm-actions">${actionLinks(item)}<button class="pm-toggle" type="button" aria-expanded="false" aria-controls="${detailId}">Summary</button></div>
        </div>
        <aside class="pm-card-meta" aria-label="Vulnerability metadata">
          <div class="meta-grid">
            <div class="meta-researcher"><span class="meta-label">RESEARCHER</span>${researcher}</div>
            <div class="meta-row"><span class="meta-label">DIFFICULTY</span><span class="meta-value ${difficultyClass(difficulty)}">${escapeHtml(difficulty)}</span></div>
            <div class="meta-row"><span class="meta-label">ADDED</span><span class="meta-value">${escapeHtml(item.added)}</span></div>
            <div class="meta-row meta-row-stack"><span class="meta-label">LANGUAGE</span><span class="meta-value">${escapeHtml(item.language)}</span></div>
          </div>
        </aside>
        <div class="pm-detail" id="${detailId}" aria-hidden="true">
          <div class="pm-questions">
            <div class="pm-question pm-syntax"><h3>Summary</h3><p>${escapeHtml(technicalSummary(item))}</p></div>
            <div class="pm-question pm-syntax"><h3>Syntax</h3><pre><code>${escapeHtml(exploitSyntax(item))}</code></pre></div>
            <div class="pm-question pm-syntax"><h3>Similar vulnerabilities</h3><div class="pm-resource-list">${relatedResources(item).map((resource) => `<a href="${safeHref(resource.url)}" ${safeExternalAttrs()}>${escapeHtml(resource.label)}</a>`).join("")}</div></div>
          </div>
        </div>
      </article>`;
  }

  function updateStats(count) {
    const dateNode = root.querySelector("[data-pm-date]");
    const countNode = root.querySelector("[data-pm-count]");
    const lastCheckNode = root.querySelector("[data-pm-last-check]");
    if (dateNode) {
      dateNode.textContent = new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", year: "numeric" }).format(archiveDate(state.day));
    }
    if (countNode) countNode.textContent = String(count);
    if (lastCheckNode) lastCheckNode.textContent = formatLastCheck(liveFeedUpdatedAt);
  }

  function formatLastCheck(value) {
    if (!value) return "--";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "--";
    return new Intl.DateTimeFormat("en-US", {
      hour: "numeric",
      minute: "2-digit",
      timeZone: "America/Chicago",
      timeZoneName: "short"
    }).format(date);
  }

  function render() {
    const items = filteredItems();
    updateStats(items.length);
    renderArchive();
    renderMenu();
    root.querySelector(".pm-feed").innerHTML = items.length
      ? items.map(card).join("")
      : '<div class="pm-panel pm-empty">No signal matched that filter. Try a broader ecosystem, severity, or tag.</div>';
    root.querySelectorAll(".pm-toggle").forEach((button) => {
      button.addEventListener("click", () => {
        const detail = root.querySelector(`#${button.getAttribute("aria-controls")}`);
        const open = button.getAttribute("aria-expanded") === "true";
        button.setAttribute("aria-expanded", String(!open));
        detail.setAttribute("aria-hidden", String(open));
      });
    });
  }

  root.querySelector('[data-filter="query"]').addEventListener("input", (event) => { state.query = event.target.value; render(); });
  root.querySelector('[data-filter="severity"]').addEventListener("change", (event) => { state.severity = event.target.value; render(); });
  root.querySelector('[data-filter="tag"]').addEventListener("input", (event) => { state.tag = event.target.value; render(); });
  root.querySelector(".pm-source-toggle").addEventListener("click", (event) => {
    const button = event.currentTarget;
    const list = root.querySelector(`#${button.getAttribute("aria-controls")}`);
    const open = button.getAttribute("aria-expanded") === "true";
    button.setAttribute("aria-expanded", String(!open));
    if (list) list.setAttribute("aria-hidden", String(open));
  });
  renderSourcePool();
  render();
  loadLiveFeed().then(render);
})();
