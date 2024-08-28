#!/usr/bin/env node

import { createInterface } from 'readline';
import psl from 'psl';
import whoiser from 'whoiser';
import dns from 'node:dns/promises';
import fs from 'fs/promises';

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
        headers = csvData.shift();
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

async function flagCDN(rowpromise) {
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

  const url = new URL("https://" + row.Domain);

  try {
    // console.error('fetching', row.Domain);
    const res = await fetch(url, { redirect: 'manual' });
    row.HTTPStatus = res.status;
    row.HTTPHeaders = Object.fromEntries(res.headers.entries());

    if (res.status === 200 && row.HTTPHeaders['content-type']?.startsWith('text/html')) {
      row.HTTPBody = await res.text();
    }
  } catch (e) {
    row.HTTPError = e;
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
  if (row.HTTPBody.match(/\/media_[a-f0-9]{40}/)) {
    row.Source = 'Helix';
    delete row.HTTPBody;
    delete row.HTTPHeaders;
  } else if (row.HTTPBody.match(/\/etc.clientlibs\//)) {
    row.Source = 'AEM';
    delete row.HTTPBody;
    delete row.HTTPHeaders;
  } else if (row.HTTPBody.match(/\/\.rum\/@adobe\/helix-rum-js/)) {
    row.Source = 'RUM';
  } else {
    row.Source = 'Other';
  }
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
  .map(enrichDNS)
  .map(enrichHTTPS)
  .map(flagCDN)
  .map(enrichHTML)
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
} catch (error) {
  console.error('Error writing to out.json:', error);
}

