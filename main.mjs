#!/usr/bin/env node

import { createInterface } from 'readline';
import psl from 'psl';
import whoiser from 'whoiser';
import dns from 'node:dns/promises';
import fs from 'fs/promises';
import puppeteer from 'puppeteer-extra';
import StealthPlugin from 'puppeteer-extra-plugin-stealth';
import pLimit from 'p-limit';

const limit = pLimit(5);
await puppeteer.use(StealthPlugin());
// Launch browser with additional options to handle protocol errors
const browser = await puppeteer.launch({
  args: [
    '--disable-gpu',
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-dev-shm-usage',
    '--ignore-certificate-errors',
  ]
});

function readCSVFromStdin() {
  return new Promise((resolve) => {
    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: false
    });

    let headers;
    let csvData = [];

    rl.on('line', (line) => {
      csvData.push(line.split(/[ \t,;]+/));
      if (!headers) {
        headers = csvData.shift()
          .map(h => h.trim())
          .map(h => h.replace(/url/, 'Domain'));

      }
    });

    rl.on('close', () => {
      resolve(csvData.map(row => row.reduce((acc, cur, i) => {
        acc[headers[i]] = cur;
        return acc;
      }, {})));
    });
  });
};

const unknownCDNS = [];

// Usage example:
const csvData = await readCSVFromStdin();

function cleanupTrailingDot(row) {
  if (row.Domain.endsWith('.')) {
    row.Domain = row.Domain.slice(0, -1);
  }
  return row;
}

function flagPorts(row) {
  if (row.Domain.indexOf(':') > -1) {
    row.Source = 'Excluded';
    row.Comment = 'Cloudflare includes ports that are non-productive, we exclude these domains';
  }
  if (row.Domain.indexOf('/') > -1) {
    // some CDNs have bad forwarded hosts, so we clean up after them
    row.Domain = row.Domain.split('/')[0];
    row.Comment = 'Removed path from domain';
  }
  return row;
}

function flagDev(row) {
  const devParents = [
    'workers.dev',
    'web.pfizer',
    'templates.pfizer',
    'oastify.com',
    'ngrok-free.app',
    'impactful-1.site',
    'impactful-2.site',
    'impactful-3.site',
    'impactful-4.site',
    'impactful-5.site',
    'hlx-1.page',
    'hlx-4.page',
    'helix3.dev',
    'helix3.page',
    'github.com',
    'github.dev',
    'franklin.pfizer',
    'fastlydemo.net',
    'fastly.net',
    'fastly-aem.page',
    'cloudfront.net',
    'bing.com',
    'aem.page',
    'aem.reviews',
    'aem.live',
    'adobeio-static.net',
    'adobeaemcloud.com',
    'adobe.pfizer',
    'adobe.net',
    'azurefd.net',
    'us-1.magentosite.cloud',
    'us-2.magentosite.cloud',
    'us-3.magentosite.cloud',
    'us-4.magentosite.cloud',
  ];
  if (devParents.includes(row.Parent) || devParents.includes(row.TLD)) {
    row.Source = 'Excluded';
    row.Comment = 'Development domain excluded';
  }
  return row;
}

function flagParent(row) {
  if (row.Source === 'Excluded') {
    return row;
  }

  row.Parent = psl.parse(row.Domain).domain;
  row.TLD = psl.parse(row.Domain).tld;
  return row;
}

async function enrichDNS(row) {
  if (row.Source === 'Excluded') {
    return row;
  }
  try {
    row.DNS = await dns.resolveAny(row.Domain);
  } catch (e) {
    row.DNSError = e;
  }
  return row;
}

function flagIP(row) {
  if (row.Source === 'Excluded') {
    return row;
  }

  // Regular expressions for IPv4 and IPv6 validation
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;

  if (ipv4Regex.test(row.Domain) || ipv6Regex.test(row.Domain)) {
    row.Source = 'Excluded';
    row.Comment = 'IP address excluded';
  }

  return row;
}

async function flagCDNFromDNS(rowpromise) {
  const row = await rowpromise;
  if (row.Source === 'Excluded') {
    return row;
  }

  if (!row.DNS) {
    return row;
  }
  const cdns = [
    {
      pattern: '.cdn.cloudflare.net',
      cdn: 'Cloudflare'
    },
    {
      pattern: '.edgekey.net',
      cdn: 'Akamai'
    },
    {
      pattern: '.edgesuite.net',
      cdn: 'Akamai'
    },
    {
      pattern: '.magentocloud.map.fastly.net',
      cdn: 'Adobe Commerce'
    },
    {
      pattern: '.fastly.net',
      cdn: 'Fastly'
    },
    {
      pattern: '.adobeaemcloud.com',
      cdn: 'AEM Cloud Service'
    },
    {
      pattern: '.cloudfront.net',
      cdn: 'Cloudfront',
    },
    {
      pattern: '.azurefd.net',
      cdn: 'Azure Front Door'
    },
    {
      pattern: '.azureedge.net',
      cdn: 'Azure Front Door',
    },
    {
      pattern: '.gammacdn.net',
      cdn: 'Edgio'
    },
    {
      pattern: '.abbottapps.net',
      cdn: 'Abbott Apps'
    },
    {
      pattern: '.cdngslb.com',
      cdn: 'Alibaba Cloud'
    },
    {
      pattern: '.induscdn.com',
      cdn: 'Indus CDN'
    },
    {
      pattern: '.impervadns.net',
      cdn: 'Imperva'
    },
    {
      pattern: '.rbzdns.com',
      cdn: 'Rackspace'
    },
    {
      pattern: '.kxcdn.com',
      cdn: 'KeyCDN'
    },
    {
      pattern: '.c10r.facebook.com',
      cdn: 'Facebook'
    },
    {
      pattern: '.radwarecloud.net',
      cdn: 'Radware Cloud'
    },
    {
      pattern: '.edgekey-staging.net',
      cdn: 'Akamai'
    },
    {
      pattern: '.azurewebsites.net',
      cdn: 'Azure Web Apps'
    },
    {
      pattern: '.x.incapdns.net',
      cdn: 'Incapsula'
    },
    {
      pattern: '.onelink-translations.com',
      cdn: 'OneLink'
    },
    {
      pattern: '.trafficmanager.net',
      cdn: 'Azure'
    },
    {
      pattern: '.trafficdirector.pfizer.net',
      cdn: 'Pfizer Traffic Director'
    },
    {
      pattern: '.wpengine.com',
      cdn: 'WP Engine'
    },
    {
      pattern: '.omicroncdn.net',
      cdn: 'Omicron CDN'
    },
    {
      pattern: '.vercel-dns.com',
      cdn: 'Vercel'
    },
    {
      pattern: '.nucdn.net',
      cdn: 'NuCDN'
    },
    {
      pattern: '.lighthouselabs.eu',
      cdn: 'Lighthouse Labs'
    },
    {
      pattern: '.github.io',
      cdn: 'GitHub Pages'
    }
  ];

  row.CDN = (await row.DNS)
    .filter(dns => dns.type === 'CNAME')
    .reduce((result, dns) => {
      if (result) return result;
      const matchedCDN = cdns.find(cdn => dns.value.endsWith(cdn.pattern));
      return matchedCDN ? matchedCDN.cdn : null;
    }, undefined);
  if (!row.CDN && row.HTTPHeaders && row.HTTPHeaders.server === 'cloudflare') {
    row.CDN = 'Cloudflare';
  }
  if (!row.CDN && row.DNSError) {
    row.CDN = 'DNS Error';
  } else if (!row.CDN && row.DNS?.find(dns => dns.type === 'CNAME')) {
    row.CDN = 'Unknown CDN ' + row.DNS.find(dns => dns.type === 'CNAME')?.value;
  }
  delete row.DNS;
  return row;
}

async function enrichHTTPS(rowpromise) {
  const row = await rowpromise;
  if (row.Source === 'Excluded') {
    return row;
  }

  const url = "https://" + row.Domain;

  try {
    const page = await browser.newPage();

    // Set shorter timeout and handle common errors
    await page.setDefaultNavigationTimeout(15000);

    // Configure request interception to handle protocol errors
    await page.setRequestInterception(true);
    page.on('request', request => {
      // Abort requests for resources we don't need
      const resourceType = request.resourceType();
      if (['image', 'stylesheet', 'font', 'script'].includes(resourceType)) {
        request.abort();
      } else {
        request.continue();
      }
    });

    const response = await page.goto(url, {
      waitUntil: 'domcontentloaded', // Changed from networkidle2 for faster response
      timeout: 15000,
      followRedirect: true,
    });

    if (response) {
      row.HTTPStatus = response.status();
      row.HTTPHeaders = response.headers();

      if (row.HTTPStatus === 200) {
        row.HTTPBody = await page.content();
      }
    }

  } catch (e) {
    console.error('Error fetching', url, e.message);
    // Set status codes for common errors
    if (e.message.includes('net::ERR_HTTP2_PROTOCOL_ERROR')) {
      row.HTTPStatus = 502;
      row.HTTPError = 'HTTP2 Protocol Error';
    } else if (e.message.includes('net::ERR_CONNECTION_TIMED_OUT')) {
      row.HTTPStatus = 504;
      row.HTTPError = 'Connection Timeout';
    } else if (e.message.includes('net::ERR_CONNECTION_REFUSED')) {
      row.HTTPStatus = 503;
      row.HTTPError = 'Connection Refused';
    } else {
      row.HTTPStatus = 500;
      row.HTTPError = e.message;
    }
  }

  return row;
}

async function enrichHTML(rowpromise) {
  const row = await rowpromise;
  if (row.Source === 'Excluded') {
    return row;
  }

  if (!row.HTTPBody) {
    row.Source = 'Unverified';
    return row;
  }
  if (row.HTTPBody.match(/\/media_[a-f0-9]{40}/) || row.HTTPBody.match(/    <header><\/header>\n    <main>/)) {
    row.Source = 'Helix';
    delete row.HTTPBody;
  } else if (row.HTTPBody.match(/\/etc.clientlibs\//)) {
    row.Source = 'AEM';
    delete row.HTTPBody;
  } else if (row.HTTPBody.match(/\/\.rum\/@adobe\/helix-rum-js/)) {
    row.Source = 'RUM';
  } else {
    row.Source = 'Other';
  }
  return row;
}

async function flagCDNFromHTTP(rowpromise) {
  const row = await rowpromise;
  if (row.Source === 'Excluded') {
    return row;
  }

  if (row.CDN && !row.CDN.startsWith('Unknown')) {
    return row;
  }

  // if there is a Server-Timing header that includes ak_p; assume Akamai
  if (row.HTTPHeaders?.['server-timing']?.includes('ak_p')) {
    row.CDN = 'Akamai';
    return row;
  }
  // if there is a server:cloudflare header; assume Cloudflare
  if (row.HTTPHeaders?.server?.includes('cloudflare')) {
    row.CDN = 'Cloudflare';
    return row;
  }
  // x-akamai-transformed header is set by Akamai
  if (row.HTTPHeaders?.['x-akamai-transformed']) {
    row.CDN = 'Akamai';
    return row;
  }
  // Server: AkamaiNetStorage
  if (row.HTTPHeaders?.server?.includes('AkamaiNetStorage')) {
    row.CDN = 'Akamai';
    return row;
  }
  // if there is any header that includes akamai in the key; assume Akamai
  if (row.HTTPHeaders && Object.keys(row.HTTPHeaders).some(key => key.toLowerCase().includes('akamai') || row.HTTPHeaders[key]?.toLowerCase()?.includes('akamai'))) {
    row.CDN = 'Akamai';
    return row;
  }
  // x-cdn: Imperva
  if (row.HTTPHeaders?.['x-cdn']?.includes('Imperva')) {
    row.CDN = 'Imperva';
    return row;
  }
  // x-azure-ref: Azure
  if (row.HTTPHeaders?.['x-azure-ref']) {
    row.CDN = 'Azure';
    return row;
  }
  // Server: Cloudfront
  if (row.HTTPHeaders?.server?.includes('CloudFront')) {
    row.CDN = 'Cloudfront';
    return row;
  }
  // akamai-x-true-cache-ttl
  if (row.HTTPHeaders?.['akamai-x-true-cache-ttl']) {
    row.CDN = 'Akamai';
    return row;
  }
  // server: ECS is EdgeCast
  if (row.HTTPHeaders?.server?.includes('ECS')) {
    row.CDN = 'EdgeCast';
    return row;
  }
  // x-amaz-cf-id: Amazon CloudFront
  if (row.HTTPHeaders?.['x-amaz-cf-id']) {
    row.CDN = 'CloudFront';
    return row;
  }
  // 'x-cache': 'Hit from cloudfront'
  if (row.HTTPHeaders?.['x-cache']?.includes(' from cloudfront')) {
    row.CDN = 'CloudFront';
    return row;
  }

  // Add x-served-by pattern detection
  if (row.HTTPHeaders?.['x-served-by']) {
    // Akamai pattern: cache-{location}{number}-{LOCATION} (e.g., cache-cph2320047-CPH)
    if (/^cache-[a-z]{3}\d+-[A-Z]{3}$/.test(row.HTTPHeaders['x-served-by'])) {
      row.CDN = 'Akamai';
      return row;
    }
    // Fastly pattern: cache-{location}-{hash}-{LOCATION} (e.g., cache-fra-eddf8230040-FRA)
    if (/^cache-[a-z]+-[a-z0-9]+-[A-Z]+$/.test(row.HTTPHeaders['x-served-by'])) {
      row.CDN = 'Fastly';
      return row;
    }
  }




  unknownCDNS.push({ domain: row.Domain, ...row.HTTPHeaders });
  row.CDN = 'Unknown CDN';
  return row;
}

// drop the first line
csvData.shift();

const cleaned = await Promise.all(csvData
  .map(cleanupTrailingDot)
  .map(flagPorts)
  .map(flagIP)
  .map(flagParent)
  .map(flagDev)
  // .filter(row => row.Source !== 'Excluded')
  //.slice(0, 1000)
  .sort((l, r) => {
    if (!l.Parent && !r.Parent) return 0;
    if (!l.Parent) return 1;
    if (!r.Parent) return -1;
    return l.Parent.localeCompare(r.Parent);
  })
  // begin the async stuff
  .map(row => limit(enrichDNS, row))
  .map(row => limit(enrichHTTPS, row))
  .map(flagCDNFromDNS)
  .map(row => limit(enrichHTML, row))
  .map(flagCDNFromHTTP)
);

function toTSV(arrOfObjects, columns) {
  // Create header row
  let tsv = columns.join('\t') + '\n';

  // Add data rows
  for (const obj of arrOfObjects) {
    const row = columns.map(col => {
      if (typeof obj[col] === 'object') {
        return JSON.stringify(obj[col]);
      }
      return obj[col] || '';
    });
    tsv += row.join('\t') + '\n';
  }

  return tsv;
}

const columns = [
  'Domain',
  'Parent',
  'Source',
  'CDN',
  'HTTPStatus',
  'Comment',
];
console.table(cleaned, columns);

try {
  await fs.writeFile('out.json', JSON.stringify(cleaned, null, 2));
  await fs.writeFile('out.tsv', toTSV(cleaned, columns));
  await fs.writeFile('unknown-cdns.json', JSON.stringify(unknownCDNS, null, 2));
} catch (error) {
  console.error('Error writing to out.json:', error);
} finally {
  if (browser) {
    try {
      await browser.close();
    } catch (e) {
      console.error('Error closing browser:', e.message);
    }
  }
}

