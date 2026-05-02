function absoluteUrl(url, base) {
  return new URL(String(url || "/"), base).toString();
}

function escapeJsonForHtml(value) {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026");
}

function segmentTitle(segment) {
  return String(segment || "")
    .replace(/^v(?=\d)/, "v")
    .replace(/-/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function breadcrumbItems(site, page, docPage, docHome) {
  const items = [{
    "@type": "ListItem",
    position: 1,
    name: "Home",
    item: absoluteUrl("/", site.url),
  }];

  const pageUrl = page?.url || "/";
  if (pageUrl === "/") {
    return items;
  }

  if (pageUrl.startsWith("/docs/")) {
    items.push({
      "@type": "ListItem",
      position: items.length + 1,
      name: "Docs",
      item: absoluteUrl("/docs/", site.url),
    });

    const activeDoc = docPage || docHome;
    if (activeDoc?.routeKind === "version") {
      items.push({
        "@type": "ListItem",
        position: items.length + 1,
        name: activeDoc.versionLabel,
        item: absoluteUrl(`/docs/${activeDoc.versionId}/`, site.url),
      });
    }

    if (docPage?.title) {
      items.push({
        "@type": "ListItem",
        position: items.length + 1,
        name: docPage.title,
        item: absoluteUrl(docPage.url, site.url),
      });
    } else if (!docHome) {
      const title = pageUrl
        .replace(/^\/docs\//, "")
        .replace(/\/$/, "")
        .split("/")
        .filter(Boolean)
        .pop();
      if (title) {
        items.push({
          "@type": "ListItem",
          position: items.length + 1,
          name: segmentTitle(title),
          item: absoluteUrl(pageUrl, site.url),
        });
      }
    }

    return items;
  }

  const title = String(pageUrl).replace(/^\/|\/$/g, "").split("/").pop();
  if (title) {
    items.push({
      "@type": "ListItem",
      position: items.length + 1,
      name: segmentTitle(title),
      item: absoluteUrl(pageUrl, site.url),
    });
  }

  return items;
}

function structuredData(site, page, docs, title, description, docPage, docHome) {
  const pageUrl = page?.url || "/";
  const canonicalUrl = absoluteUrl(pageUrl, site.url);
  const pageTitle = title || site.title;
  const pageDescription = description || site.description;
  const organizationId = absoluteUrl("/#organization", site.url);
  const websiteId = absoluteUrl("/#website", site.url);
  const pageId = `${canonicalUrl}#webpage`;
  const organization = {
    "@type": "Organization",
    "@id": organizationId,
    name: "HASP",
    legalName: "Wraxle LLC",
    url: absoluteUrl("/", site.url),
  };

  if (Array.isArray(site.sameAs) && site.sameAs.length) {
    organization.sameAs = site.sameAs;
  }

  const graph = [
    organization,
    {
      "@type": "WebSite",
      "@id": websiteId,
      name: "HASP",
      url: absoluteUrl("/", site.url),
      description: site.description,
      publisher: { "@id": organizationId },
      inLanguage: "en",
    },
    {
      "@type": pageUrl.startsWith("/docs/") && docPage ? "TechArticle" : "WebPage",
      "@id": pageId,
      url: canonicalUrl,
      name: pageTitle,
      headline: docPage?.title || pageTitle,
      description: pageDescription,
      isPartOf: { "@id": websiteId },
      publisher: { "@id": organizationId },
      inLanguage: "en",
    },
  ];

  if (pageUrl === "/") {
    graph.push({
      "@type": "SoftwareApplication",
      "@id": absoluteUrl("/#software", site.url),
      name: "HASP",
      applicationCategory: "DeveloperApplication",
      operatingSystem: "macOS, Linux",
      softwareVersion: docs?.version || site.version,
      url: absoluteUrl("/", site.url),
      description: site.description,
      publisher: { "@id": organizationId },
    });
  }

  const breadcrumbs = breadcrumbItems(site, page, docPage, docHome);
  if (breadcrumbs.length > 1) {
    graph.push({
      "@type": "BreadcrumbList",
      "@id": `${canonicalUrl}#breadcrumb`,
      itemListElement: breadcrumbs,
    });
  }

  return `<script type="application/ld+json">${escapeJsonForHtml({
    "@context": "https://schema.org",
    "@graph": graph,
  })}</script>`;
}

function sitemapUrls(docs) {
  const urls = new Set([
    "/",
    "/comparison/",
    "/docs/versions/",
  ]);

  for (const home of docs?.homes || []) {
    urls.add(home.url);
  }
  for (const page of docs?.pages || []) {
    urls.add(page.url);
  }

  return [...urls].sort((a, b) => a.localeCompare(b));
}

export default async function (eleventyConfig) {
  eleventyConfig.addPassthroughCopy({ "src/assets": "assets" });
  eleventyConfig.addPassthroughCopy({ "src/public": "/" });

  eleventyConfig.addWatchTarget("src/assets/");
  eleventyConfig.addWatchTarget("../../public/");
  eleventyConfig.addWatchTarget("../../docs/agent-profiles/");

  eleventyConfig.addFilter("absoluteUrl", absoluteUrl);
  eleventyConfig.addFilter("json", (value) => JSON.stringify(value));
  eleventyConfig.addFilter("sitemapUrls", sitemapUrls);
  eleventyConfig.addShortcode("structuredData", structuredData);

  return {
    dir: {
      input: "src",
      output: "_site",
      includes: "_includes",
      data: "_data",
    },
    templateFormats: ["njk", "md", "html"],
    htmlTemplateEngine: "njk",
    markdownTemplateEngine: "njk",
  };
}
