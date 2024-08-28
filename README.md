# sitealyzer
Take a list of sites, provide some analysis

## Usage

Copy the list of sites from Google Sheets

```bash
pbpaste | ./main.mjs
```

The results are in `out.json` and `out.tsv` files. The TSV file can be copied back into Google Sheets