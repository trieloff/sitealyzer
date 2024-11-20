#!/usr/bin/env node

import { readCSVFromStdin } from './utils.mjs';
import fs from 'fs/promises';
import levenshtein from 'js-levenshtein';

const csvData = await readCSVFromStdin();


const customers = (await fs.readFile('customers.tsv', 'utf-8'))
  .split('\n')
  .filter(line => line.trim());

import OpenAI from 'openai';

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

async function classifyDomain(domain) {
  // sort customers by levenshtein distance to the domain, lowercased, take the top 10
  const distance = customers.map(c => ({ customer: c, distance: levenshtein(c.toLowerCase(), domain.toLowerCase()) }));
  const topTen = distance.sort((a, b) => a.distance - b.distance).slice(0, 10);

  // ask o1 if the domain belongs to any of the top ten customers
  const background0 = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    temperature: 0,
    messages: [{
      role: "user", content: `Give me some background info on ${domain}. 
      Which of the following customers does it belong to? ${topTen.map(t => t.customer).join('\n')}.
      Return only the name of the most likely customer, nothing else.
      If none of the customers match, return "UNKNOWN".`
    }],
  });
  const oneShotGuess = background0.choices[0].message.content;
  if (oneShotGuess !== 'UNKNOWN') {
    return 'CERTAINLY\t' + oneShotGuess;
  }

  // get background info for the domain, by prompting o1
  const background = await openai.chat.completions.create({
    model: "gpt-4o",
    temperature: 0,
    messages: [{
      role: "user", content: `Give me some background info on ${domain}. 
      Which of the following customers does it belong to? ${customers.join('\n')}.
      Return the names of the three most likely customers, separated by line breaks.
      Only return the names, nothing else.` }],
  });
  const customerName = background.choices[0].message.content;
  const customerNames = customerName.split('\n');
  // sort customers (lower case) by levenshtein distance to each of the customer names (lower case)
  // return the top three for each of the customer names
  const result = new Set();
  for (const customer of customerNames) {
    const distance = customers.map(c => ({ customer: c, distance: levenshtein(c.toLowerCase(), customer.toLowerCase()) }));
    const topThree = distance.sort((a, b) => a.distance - b.distance).slice(0, 3);
    for (const d of topThree) {
      result.add(d.customer);
    }
  }

  // with the smaller result set, ask o1 again 
  const background2 = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    temperature: 0,
    messages: [{
      role: "user", content: `Give me some background info on ${domain}. 
      Which of the following customers does it belong to? ${Array.from(result).join('\n')}.
      Return only the name of the most likely customer, nothing else.
      If none of the customers match, return "UNKNOWN".`
    }],
  });
  if (background2.choices[0].message.content !== 'UNKNOWN') {
    return 'MAYBE\t' + background2.choices[0].message.content;
  }

  return 'UNKNOWN';
}

console.log('domain\tprobability\tcustomer');
// loop through the first 10 lines of csvData, classify each domain
for (const line of csvData) {
  const domain = line.Parent || line.Domain;
  const customer = await classifyDomain(domain);
  console.log(`${domain}\t${customer}`);
}
