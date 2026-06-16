# Svikruti Launch Website

The launch website is a static GitHub Pages site under `site/`.

It is intentionally plain HTML/CSS:

- no server
- no build step
- no paid hosting
- no Streamlit dependency
- no JavaScript framework

## Local Preview

From the repository root:

```bash
python3 -m http.server 8765
```

Open:

```text
http://127.0.0.1:8765/site/
```

## GitHub Pages Deployment

The site is currently published from the `gh-pages` branch:

```text
https://chevauxenbois.github.io/svikruti/
```

The source files live under `site/` on `main`. To republish after changing the
site, split and push the `site/` subtree:

```text
git subtree split --prefix site -b gh-pages-deploy
git push origin gh-pages-deploy:gh-pages --force-with-lease
```

For a custom domain, point the domain or subdomain to GitHub Pages and add a
`CNAME` file under `site/`.

## Contact Form

The contact CTA links to a Google Form:

```text
https://forms.gle/TaBLyFdXdmP1XMek8
```

This keeps the site static and free while allowing private inbound interest,
DPDPA journey conversations, product assistance requests, and hosted-edition
feedback.

If the form link changes, update `site/index.html`. Because the form collects
visitor contact details through Google Forms, mention that processor in any
future public privacy notice for the site.
