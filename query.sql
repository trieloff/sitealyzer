WITH alldata AS (
SELECT hostname as Domain, CAST(SUM(pageviews) / 1000 AS INT64) AS pageviews_k, APPROX_TOP_COUNT(url, 1)[OFFSET(0)].value AS topurl
FROM `helix-225321.helix_rum.PAGEVIEWS_V5`("-", 0, 90, "", "", "UTC", "all", @domainkey)
GROUP BY hostname
ORDER BY pageviews_k DESC
)
SELECT Domain, topurl, pageviews_k FROM alldata
WHERE alldata.pageviews_k > 1
