import whoiser from 'whoiser';

export default async function getOrgnameFromWhois(domain) {
  try {
    const result = await whoiser(domain);
    const [matches] = Object.entries(result)
      .map(([key, value]) => ({
        ...Object.fromEntries(Object.entries(value)
          .filter(([key, value]) => key === 'Registrant Organization')
        ),
        from: key,
      }))
      .filter(row => row['Registrant Organization']);
    return matches['Registrant Organization'];
  } catch (e) {
    return null;
  }
}

process.argv.slice(2).forEach(async (domain) => {
  console.log(domain, await getOrgnameFromWhois(domain));
});