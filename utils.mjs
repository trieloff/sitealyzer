import { createInterface } from 'readline';


export function readCSVFromStdin() {
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
          .map(h => h.replace(/^url$/, 'Domain'));

      }
    });

    rl.on('close', () => {
      resolve(csvData.map(row => row.reduce((acc, cur, i) => {
        acc[headers[i]] = cur;
        return acc;
      }, {})));
    });
  });
}
