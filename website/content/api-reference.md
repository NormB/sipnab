+++
title = "OpenAPI Reference"
description = "The interactive OpenAPI 3.1 reference for sipnab's REST API, generated from the request handlers themselves and rendered with Scalar. Every route, parameter, response shape and status code the server actually serves."
template = "page.html"

[extra]
openapi_reference = true
+++

# OpenAPI reference

This page renders sipnab's OpenAPI 3.1 document. sipnab generates that document
from the REST handlers themselves, so the routes the server serves and the
routes this page shows are one list by construction rather than by
proofreading.

The machine-readable file lives at
[/openapi.json](https://sipnab.com/openapi.json). Point any OpenAPI tool at it:
a client generator, a schema validator, or your editor.

For the written reference -- how to choose an API key, what the two
authentication schemes are for, the bind-address rules, and the curl and jq
recipes -- read [REST API](@/docs/api.md). This page is the mechanical half:
the shape of every request and every response.

## Three things to know before you read it

**The document describes a full build.** A route appears here when the build
serving it compiles the feature behind it. A build without vCon export answers
no `/v1/dialogs/{call_id}/vcon`, and the document that build generates lists
none. The published document covers everything, so read it as the ceiling
rather than as a promise about the binary you are running.

**This page cannot send a request, and does not offer to.** Your sipnab runs on
your own machine, and this site's Content Security Policy lets the page reach
this site and nowhere else. A "send request" button here could never reach your
capture, so the page hides it rather than letting it fail in a way that reads
as a broken API.

**Nothing here leaves your browser.** This site serves the Scalar renderer
itself, with telemetry off and the request proxy empty, so the page contacts no
other host.

<div id="scalar-app" data-openapi-url="/openapi.json"></div>

<noscript>
The interactive reference needs JavaScript. Without it, read
<a href="https://sipnab.com/openapi.json">/openapi.json</a> directly, or the
written reference on the <a href="/docs/api/">REST API</a> page.
</noscript>
