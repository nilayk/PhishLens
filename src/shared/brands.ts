/**
 * Brand identity table.
 *
 * Two jobs:
 *  1. Recognise a *claimed* identity from a display name, subject, or body ("Microsoft Account
 *     Team", "your PayPal account").
 *  2. Know which registrable domains legitimately belong to that brand, so a claim can be checked
 *     against the actual sender domain.
 *
 * `keywords` are matched against confusable-folded text, so `paypa1` and `pаypal` both hit `paypal`.
 * `lookalikeTargets` are the strings that typosquatting is measured against.
 */
export interface Brand {
  id: string;
  /** Display label used in explanations. */
  label: string;
  /** Folded tokens that indicate the message claims to be this brand. */
  keywords: readonly string[];
  /** Registrable domains this brand legitimately sends from or links to. */
  domains: readonly string[];
  /** Strings that a lookalike domain would be imitating (registrable-domain form). */
  lookalikeTargets: readonly string[];
}

export const BRANDS: readonly Brand[] = [
  {
    id: 'microsoft',
    label: 'Microsoft',
    keywords: ['microsoft', 'office365', 'office 365', 'onedrive', 'sharepoint', 'outlook', 'msteams', 'microsoftteams', 'windowsdefender', 'azuread', 'entraid'],
    domains: [
      'microsoft.com', 'microsoftonline.com', 'office.com', 'office365.com', 'live.com',
      'outlook.com', 'sharepoint.com', 'onedrive.com', 'azure.com', 'windows.com',
      'msn.com', 'microsoft365.com', 'skype.com', 'xbox.com', 'msftauth.net',
      'microsoftstream.com', 'office.net', 'msidentity.com', 'linkedin.com', 'github.com',
    ],
    lookalikeTargets: ['microsoft.com', 'microsoftonline.com', 'office365.com', 'sharepoint.com', 'onedrive.com'],
  },
  {
    id: 'google',
    label: 'Google',
    keywords: ['google', 'gmail', 'googledrive', 'googleworkspace', 'gsuite', 'youtube', 'googlepay'],
    domains: [
      'google.com', 'gmail.com', 'googlemail.com', 'youtube.com', 'googleapis.com',
      'withgoogle.com', 'google.co.uk', 'googleusercontent.com', 'goo.gl', 'firebase.google.com',
      'accounts.google.com', 'gstatic.com', 'chromium.org', 'android.com',
    ],
    lookalikeTargets: ['google.com', 'gmail.com', 'youtube.com', 'googlemail.com'],
  },
  {
    id: 'paypal',
    label: 'PayPal',
    keywords: ['paypal', 'paypalcredit', 'venmo'],
    domains: ['paypal.com', 'paypal.co.uk', 'paypal.me', 'paypalobjects.com', 'venmo.com', 'paypal-communication.com', 'paypal.de', 'paypal.fr'],
    lookalikeTargets: ['paypal.com', 'paypal.co.uk', 'venmo.com'],
  },
  {
    id: 'apple',
    label: 'Apple',
    keywords: ['apple', 'appleid', 'icloud', 'itunes', 'appstore', 'applepay'],
    domains: ['apple.com', 'icloud.com', 'itunes.com', 'me.com', 'mac.com', 'apple.co', 'apple.news'],
    lookalikeTargets: ['apple.com', 'icloud.com', 'appleid.apple.com'],
  },
  {
    id: 'amazon',
    label: 'Amazon',
    keywords: ['amazon', 'amazonprime', 'aws', 'amazonwebservices', 'kindle', 'audible'],
    domains: [
      'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.ca', 'amazon.in',
      'amazon.co.jp', 'amazon.com.au', 'amazonaws.com', 'aws.amazon.com', 'audible.com',
      'primevideo.com', 'amazonses.com', 'kindle.com', 'amazon.jobs',
    ],
    lookalikeTargets: ['amazon.com', 'amazon.co.uk', 'amazonaws.com'],
  },
  {
    id: 'netflix',
    label: 'Netflix',
    keywords: ['netflix'],
    domains: ['netflix.com', 'nflxext.com', 'netflix.net'],
    lookalikeTargets: ['netflix.com'],
  },
  {
    id: 'docusign',
    label: 'DocuSign',
    keywords: ['docusign', 'docu sign', 'adobesign', 'echosign', 'hellosign', 'dropboxsign'],
    domains: ['docusign.com', 'docusign.net', 'adobesign.com', 'echosign.com', 'hellosign.com', 'dropboxsign.com'],
    lookalikeTargets: ['docusign.com', 'docusign.net'],
  },
  {
    id: 'dropbox',
    label: 'Dropbox',
    keywords: ['dropbox'],
    domains: ['dropbox.com', 'dropboxusercontent.com', 'dropboxstatic.com'],
    lookalikeTargets: ['dropbox.com'],
  },
  {
    id: 'adobe',
    label: 'Adobe',
    keywords: ['adobe', 'acrobat', 'creativecloud'],
    domains: ['adobe.com', 'adobe.io', 'adobelogin.com', 'acrobat.com'],
    lookalikeTargets: ['adobe.com', 'acrobat.com'],
  },
  {
    id: 'linkedin',
    label: 'LinkedIn',
    keywords: ['linkedin'],
    domains: ['linkedin.com', 'licdn.com', 'lnkd.in'],
    lookalikeTargets: ['linkedin.com'],
  },
  {
    id: 'meta',
    label: 'Meta / Facebook',
    keywords: ['facebook', 'instagram', 'whatsapp', 'metabusiness', 'meta platforms'],
    domains: ['facebook.com', 'facebookmail.com', 'instagram.com', 'whatsapp.com', 'meta.com', 'fb.com', 'fb.me'],
    lookalikeTargets: ['facebook.com', 'instagram.com', 'whatsapp.com'],
  },
  {
    id: 'dhl',
    label: 'DHL',
    keywords: ['dhl'],
    domains: ['dhl.com', 'dhl.de', 'dhlparcel.com', 'dhlexpress.com', 'dhl.co.uk'],
    lookalikeTargets: ['dhl.com'],
  },
  {
    id: 'fedex',
    label: 'FedEx',
    keywords: ['fedex'],
    domains: ['fedex.com', 'fedex.co.uk', 'fedexoffice.com'],
    lookalikeTargets: ['fedex.com'],
  },
  {
    id: 'ups',
    label: 'UPS',
    keywords: ['ups package', 'united parcel'],
    domains: ['ups.com', 'ups.co.uk'],
    lookalikeTargets: ['ups.com'],
  },
  {
    id: 'usps',
    label: 'USPS',
    keywords: ['usps', 'united states postal'],
    domains: ['usps.com', 'usps.gov', 'uspis.gov'],
    lookalikeTargets: ['usps.com'],
  },
  {
    id: 'chase',
    label: 'Chase',
    keywords: ['chase bank', 'jpmorgan', 'chase online'],
    domains: ['chase.com', 'jpmorgan.com', 'jpmorganchase.com', 'chasepaymentech.com'],
    lookalikeTargets: ['chase.com'],
  },
  {
    id: 'bankofamerica',
    label: 'Bank of America',
    keywords: ['bank of america', 'bankofamerica', 'bofa'],
    domains: ['bankofamerica.com', 'bofa.com', 'merrilledge.com', 'ml.com'],
    lookalikeTargets: ['bankofamerica.com'],
  },
  {
    id: 'wellsfargo',
    label: 'Wells Fargo',
    keywords: ['wells fargo', 'wellsfargo'],
    domains: ['wellsfargo.com', 'wf.com', 'wellsfargoadvisors.com'],
    lookalikeTargets: ['wellsfargo.com'],
  },
  {
    id: 'hsbc',
    label: 'HSBC',
    keywords: ['hsbc'],
    domains: ['hsbc.com', 'hsbc.co.uk', 'hsbc.ca', 'hsbcnet.com'],
    lookalikeTargets: ['hsbc.com', 'hsbc.co.uk'],
  },
  {
    id: 'amex',
    label: 'American Express',
    keywords: ['american express', 'americanexpress', 'amex'],
    domains: ['americanexpress.com', 'aexp.com', 'amex.com', 'americanexpress.co.uk'],
    lookalikeTargets: ['americanexpress.com'],
  },
  {
    id: 'intuit',
    label: 'Intuit / QuickBooks',
    keywords: ['intuit', 'quickbooks', 'turbotax'],
    domains: ['intuit.com', 'quickbooks.com', 'turbotax.com', 'intuit.ca', 'mint.com'],
    lookalikeTargets: ['intuit.com', 'quickbooks.com'],
  },
  {
    id: 'irs',
    label: 'IRS',
    keywords: ['irs', 'internal revenue'],
    domains: ['irs.gov', 'treasury.gov', 'eftps.gov'],
    lookalikeTargets: ['irs.gov'],
  },
  {
    id: 'hmrc',
    label: 'HMRC',
    keywords: ['hmrc', 'hm revenue'],
    domains: ['hmrc.gov.uk', 'gov.uk', 'tax.service.gov.uk'],
    lookalikeTargets: ['hmrc.gov.uk'],
  },
  {
    id: 'coinbase',
    label: 'Coinbase',
    keywords: ['coinbase'],
    domains: ['coinbase.com', 'coinbase.email'],
    lookalikeTargets: ['coinbase.com'],
  },
  {
    id: 'binance',
    label: 'Binance',
    keywords: ['binance'],
    domains: ['binance.com', 'binance.us'],
    lookalikeTargets: ['binance.com'],
  },
  {
    id: 'okta',
    label: 'Okta',
    keywords: ['okta'],
    domains: ['okta.com', 'oktapreview.com', 'okta-emea.com'],
    lookalikeTargets: ['okta.com'],
  },
  {
    id: 'zoom',
    label: 'Zoom',
    keywords: ['zoom meeting', 'zoom video', 'zoom.us'],
    domains: ['zoom.us', 'zoom.com', 'zoomgov.com'],
    lookalikeTargets: ['zoom.us', 'zoom.com'],
  },
  {
    id: 'slack',
    label: 'Slack',
    keywords: ['slack'],
    domains: ['slack.com', 'slack-edge.com', 'slackhq.com'],
    lookalikeTargets: ['slack.com'],
  },
  {
    id: 'salesforce',
    label: 'Salesforce',
    keywords: ['salesforce'],
    domains: ['salesforce.com', 'force.com', 'salesforce-communications.com', 'pardot.com'],
    lookalikeTargets: ['salesforce.com'],
  },
  {
    id: 'wetransfer',
    label: 'WeTransfer',
    keywords: ['wetransfer'],
    domains: ['wetransfer.com', 'wetransfer.net'],
    lookalikeTargets: ['wetransfer.com'],
  },
  {
    id: 'stripe',
    label: 'Stripe',
    keywords: ['stripe payments', 'stripe dashboard'],
    domains: ['stripe.com', 'stripe.dev'],
    lookalikeTargets: ['stripe.com'],
  },
  {
    id: 'shopify',
    label: 'Shopify',
    keywords: ['shopify'],
    domains: ['shopify.com', 'myshopify.com', 'shopifyemail.com'],
    lookalikeTargets: ['shopify.com'],
  },
  {
    id: 'steam',
    label: 'Steam',
    keywords: ['steam community', 'steampowered', 'valve corporation'],
    domains: ['steampowered.com', 'steamcommunity.com', 'valvesoftware.com'],
    lookalikeTargets: ['steampowered.com', 'steamcommunity.com'],
  },
  {
    id: 'spotify',
    label: 'Spotify',
    keywords: ['spotify'],
    domains: ['spotify.com', 'spotifymail.com'],
    lookalikeTargets: ['spotify.com'],
  },
];

const BRAND_BY_DOMAIN = new Map<string, Brand>();
for (const brand of BRANDS) {
  for (const domain of brand.domains) {
    if (!BRAND_BY_DOMAIN.has(domain)) BRAND_BY_DOMAIN.set(domain, brand);
  }
}

export function brandOwningDomain(registrable: string): Brand | undefined {
  return BRAND_BY_DOMAIN.get(registrable);
}
