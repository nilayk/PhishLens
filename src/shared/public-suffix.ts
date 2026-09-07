/**
 * A curated multi-label public-suffix table.
 *
 * This is deliberately *not* the full Public Suffix List: shipping the PSL means either a
 * dependency or a ~250 KB data file with a refresh story, and this extension has a zero-runtime-
 * dependency budget. The entries below are the multi-label suffixes that actually show up in
 * phishing and in legitimate corporate mail. Anything not listed falls back to "last two labels",
 * which is correct for the overwhelming majority of hostnames.
 *
 * Documented as a known limitation in docs/ARCHITECTURE.md §10.
 */
export const MULTI_LABEL_SUFFIXES: ReadonlySet<string> = new Set([
  // United Kingdom
  'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'sch.uk', 'ac.uk', 'gov.uk', 'nhs.uk',
  'police.uk', 'mod.uk',
  // Ireland / Europe
  'gov.ie', 'com.es', 'org.es', 'gob.es', 'edu.es', 'com.pt', 'gov.pt', 'com.pl', 'gov.pl',
  'com.gr', 'gov.gr', 'com.ro', 'com.ua', 'gov.ua', 'com.tr', 'gov.tr', 'edu.tr', 'com.hr',
  'com.cy', 'co.at', 'or.at', 'gv.at', 'co.no',
  // Australia / New Zealand
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz', 'school.nz',
  // Asia
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp', 'lg.jp',
  'co.kr', 'or.kr', 'go.kr', 'ne.kr', 're.kr',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
  'com.hk', 'org.hk', 'edu.hk', 'gov.hk', 'com.tw', 'org.tw', 'gov.tw', 'edu.tw',
  'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg',
  'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my',
  'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in', 'edu.in', 'res.in', 'firm.in', 'gen.in',
  'com.ph', 'gov.ph', 'com.vn', 'gov.vn', 'com.id', 'co.id', 'or.id', 'ac.id', 'go.id',
  'com.bd', 'com.pk', 'com.np', 'com.lk', 'com.kh',
  // Middle East
  'com.sa', 'gov.sa', 'edu.sa', 'co.il', 'org.il', 'gov.il', 'ac.il', 'com.ae', 'gov.ae',
  'com.qa', 'com.kw', 'com.bh', 'com.om', 'com.jo', 'com.lb',
  // Africa
  'co.za', 'org.za', 'gov.za', 'ac.za', 'net.za', 'com.ng', 'gov.ng', 'com.eg', 'gov.eg',
  'co.ke', 'go.ke', 'ac.ke', 'com.gh', 'co.tz', 'com.ma', 'com.tn', 'com.dz',
  // Americas
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br', 'com.mx', 'gob.mx', 'edu.mx',
  'com.ar', 'gob.ar', 'com.co', 'gov.co', 'edu.co', 'com.pe', 'gob.pe', 'com.cl', 'gob.cl',
  'com.ve', 'com.ec', 'com.uy', 'com.py', 'com.bo', 'com.do', 'com.gt', 'com.pa',
  // Russia / CIS
  'com.ru', 'net.ru', 'org.ru', 'gov.ru', 'com.by', 'com.kz', 'org.kz', 'gov.kz',
  // Generic / delegated
  'co.com',
]);

/**
 * Hosts where anyone can publish in seconds. A page under one of these is not inherently malicious —
 * plenty of real products live here — but the address says nothing about who wrote the page, which is
 * what matters when the page is asking for credentials.
 *
 * Two shapes, matched by the same `host === suffix || host.endsWith('.' + suffix)` test:
 *
 *  - **Suffixes**, where the tenant gets a subdomain: `victim-login.pages.dev`.
 *  - **Whole hosts**, where the tenant gets a *path*: `storage.googleapis.com/<bucket>/page.html`.
 *    These are the ones worth being careful about, because the visible domain belongs to Google,
 *    Amazon or Microsoft and reads as impeccable. That is precisely why phishing kits are served from
 *    them, and the reason a suffix-only list had a hole exactly where the most reputable-looking
 *    addresses are.
 *
 * A curated subset, like the rest of this file. Regional forms that cannot be expressed as a suffix
 * (`s3.eu-west-1.amazonaws.com`, `objectstorage.<region>.oraclecloud.com`) are not covered; the
 * alternative is matching `amazonaws.com` wholesale, which would flag every service AWS hosts.
 */
export const OPEN_HOSTING_SUFFIXES: readonly string[] = [
  'web.app', 'firebaseapp.com', 'pages.dev', 'workers.dev', 'r2.dev', 'trycloudflare.com',
  'vercel.app', 'netlify.app', 'netlify.com', 'surge.sh', 'github.io', 'gitlab.io',
  'glitch.me', 'repl.co', 'replit.app', 'onrender.com', 'fly.dev', 'railway.app',
  'herokuapp.com', 'azurewebsites.net', 'blob.core.windows.net', 'appspot.com',
  'weeblysite.com', 'weebly.com', 'wixsite.com', 'square.site', 'godaddysites.com',
  'blogspot.com', 'wordpress.com', 'ngrok.io', 'ngrok-free.app', 'ngrok.app',
  'duckdns.org', 'no-ip.org', 'hopto.org', 'serveo.net', 'localtunnel.me',
  '000webhostapp.com', 'infinityfreeapp.com', 'freehostia.com', 'byethost.com',
  'sharepoint-online.com', 'my-sharepoint.com',
  // Object stores: the bucket is a path segment, so the hostname itself is the open host.
  'storage.googleapis.com', 'firebasestorage.googleapis.com', 's3.amazonaws.com',
  'r2.cloudflarestorage.com', 'digitaloceanspaces.com', 'backblazeb2.com', 'wasabisys.com',
  'storage.yandexcloud.net', 'githubusercontent.com', 'dropboxusercontent.com',
];

/** Consumer mailbox providers. A sender here cannot legitimately *be* a corporation. */
export const FREEMAIL_DOMAINS: ReadonlySet<string> = new Set([
  'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'yahoo.co.jp', 'ymail.com',
  'rocketmail.com', 'hotmail.com', 'hotmail.co.uk', 'outlook.com', 'outlook.co.uk', 'live.com',
  'live.co.uk', 'msn.com', 'aol.com', 'aim.com', 'icloud.com', 'me.com', 'mac.com',
  'protonmail.com', 'proton.me', 'pm.me', 'tutanota.com', 'tuta.io', 'zoho.com', 'zohomail.com',
  'gmx.com', 'gmx.de', 'gmx.net', 'web.de', 't-online.de', 'mail.com', 'mail.ru', 'yandex.ru',
  'yandex.com', 'inbox.ru', 'list.ru', 'bk.ru', 'rediffmail.com', 'qq.com', '163.com', '126.com',
  'naver.com', 'daum.net', 'hanmail.net', 'seznam.cz', 'orange.fr', 'wanadoo.fr', 'free.fr',
  'laposte.net', 'libero.it', 'virgilio.it', 'terra.com.br', 'uol.com.br', 'bol.com.br',
  'fastmail.com', 'hushmail.com', 'mailfence.com', 'runbox.com', 'posteo.de',
]);

/**
 * Disposable / throwaway mailbox providers. Legitimate business mail does not originate here.
 */
export const DISPOSABLE_DOMAINS: ReadonlySet<string> = new Set([
  'mailinator.com', 'guerrillamail.com', 'sharklasers.com', 'yopmail.com', '10minutemail.com',
  'temp-mail.org', 'tempmail.com', 'throwawaymail.com', 'trashmail.com', 'getnada.com',
  'dispostable.com', 'maildrop.cc', 'fakeinbox.com', 'mytemp.email', 'moakt.com',
  'emailondeck.com', 'burnermail.io', 'mailnesia.com', 'inboxbear.com', 'tempr.email',
]);

/** URL shorteners: they hide the real destination, which is the whole point. */
export const URL_SHORTENERS: ReadonlySet<string> = new Set([
  'bit.ly', 'bitly.com', 'j.mp', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'buff.ly',
  'is.gd', 'v.gd', 'cutt.ly', 'rebrand.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 'soo.gd',
  'clck.ru', 'vk.cc', 'qps.ru', 'u.to', 'gg.gg', 'shrtco.de', 'short.io', 'bl.ink',
  'lnkd.in', 'db.tt', 'youtu.be', 'amzn.to', 'apple.co', 'fb.me', 'trib.al', 'ift.tt',
  'mzl.la', 'wp.me', 'dlvr.it', 'zpr.io', 'hyperurl.co', 'linktr.ee', 'bio.link',
  's.id', 'urlz.fr', 'cutt.us', 'tny.im', 'shorte.st', 'adf.ly', 'bc.vc', 'ouo.io',
]);

/**
 * Hosts that legitimately perform link tracking/redirection on behalf of senders. Their presence is
 * expected in real marketing mail, so they must not be treated as "suspicious redirect".
 *
 * A convenience, not the mechanism. Any list of platforms is out of date the day it is written, so
 * the load-bearing check is `LinkAnalysis.onSenderDomain`, which recognises the same rewrite from its
 * shape. This list adds the case that check cannot see: a sender on its own domain whose links are
 * rewritten to the platform's domain.
 */
export const KNOWN_TRACKING_REDIRECTORS: ReadonlySet<string> = new Set([
  'google.com', 'www.google.com', 'links.google.com',
  'click.mail.google.com', 'notifications.google.com',
  'sendgrid.net', 'ct.sendgrid.net', 'url1234.sendgrid.net',
  'mailchimp.com', 'list-manage.com', 'mandrillapp.com', 'mcusercontent.com',
  'salesforce.com', 'pardot.com', 'exacttarget.com', 'exct.net', 'et.email',
  'hubspotlinks.com', 'hs-sites.com', 'hubspotemail.net',
  'sparkpostmail.com', 'mailgun.org', 'postmarkapp.com', 'pstmrk.it',
  'braze.com', 'sailthru.com', 'iterable.com', 'links.iterable.com',
  'klaviyomail.com', 'customeriomail.com', 'intercom-mail.com',
  'awstrack.me', 'amazonses.com', 'ses.amazonaws.com',
  'safelinks.protection.outlook.com', 'protection.outlook.com',
  'urldefense.com', 'urldefense.proofpoint.com', 'proofpoint.com',
  'clicktime.symantec.com', 'mimecast.com', 'protect-us.mimecast.com',
  'barracudanetworks.com', 'linkprotect.cudasvc.com',
  // Newsletter platforms. Included because a writer on a custom domain still has every link rewritten
  // to the platform's, which `onSenderDomain` cannot recognise.
  'substack.com', 'email.mg1.substack.com', 'email.mg2.substack.com',
  'beehiiv.com', 'mail.beehiiv.com', 'link.mail.beehiiv.com',
  'convertkit-mail.com', 'convertkit-mail2.com', 'kit.com',
  'ghost.io', 'buttondown.email', 'mailerlite.com',
  'rs6.net', 'cmail19.com', 'cmail20.com', 'activehosted.com',
  'aweber.com', 'getresponse.com', 'mailjet.com', 'omnisend.com',
  'sendinblue.com', 'brevo.com', 'klclick.com',
]);
