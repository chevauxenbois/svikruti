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

The workflow is `.github/workflows/pages.yml`.

After this lands on `main`, enable GitHub Pages in the repository settings:

1. Go to repository Settings.
2. Open Pages.
3. Set Source to **GitHub Actions**.
4. Run the `Svikruti Launch Site` workflow if it does not run automatically.

The free URL should be:

```text
https://chevauxenbois.github.io/svikruti/
```

If you later buy a domain such as `svikruti.in` or `svikruti.dev`, point it to
GitHub Pages and add a `CNAME` file under `site/`.

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
