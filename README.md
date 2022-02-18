## HC SVNT DRACONES
**As of 2022-02-18, this _seems_ to work for _very_ old browsers ... specifically, those that don't support the HTTP `CONNECT` verb.**

At the very least, it appear to successfully proxy non-secure _HTTP_ traffic, including files, without incident.

For most people: if this doesn't work straight off for you, you're probably better off trying something else first _(e.g. tenox7/wrp, atauenis/WebOne, Jonathanalland.com/legacy-mac-proxy at https://jonathanalland.com/old-osx-projects.html, or something involving `squid`)_.

## Tl;dr: Run, while you still can.

If I ever do something with this _(that seems useful and stable)_, I'll submit it back to the original (zenwheel/legacyproxy) with a PR. - Jim

P.S. There is newer stuff _(including [tons of notes](https://github.com/jgrisham/legacyproxy/blob/testing_2022-02-16/proxy.rb))_ in the `testing_2022-02-16` branch of this fork.

<hr />

<details><summary>(original content of this `README.md`)</summary>

The internet has changed a lot in the past decade or two and has left some of the vintage computers that built it behind.  This is an HTTP proxy that can be used to access modern content on older browsers.

### Installation

I intended to run this on a Raspberry Pi, the installation procedure I used was:

		sudo apt-get install ruby2.3 ruby2.3-dev build-essential patch zlib1g-dev liblzma-dev libmagickwand-dev
		sudo gem install bundler
		bundle install

Then to run the proxy, just start `ruby ./proxy.rb` in a shell.

I didn't use this, but on `ubuntu 14.04` this should be pretty close to what you need:

		sudo apt-get install software-properties-common
		sudo apt-add-repository ppa:brightbox/ruby-ng
		sudo apt-get update
		sudo apt-get install ruby2.4 ruby2.4-dev build-essential patch zlib1g-dev liblzma-dev libmagickwand-dev
		sudo gem install bundler
		bundle install

Lastly, on macOS the only weird thing I needed was to `brew install imagemagick@6`, the default `imagemagick` version didn't work with `rmagick`.

### Usage

I built it to work with Netscape 1.0N.  Due to SSL, CSS, tables and a few other things that have changed on the web, it didn't work very well.  To use the proxy: choose "Preferences..." from the "Options" menu, select "Proxies" from the popup menu at the top.  For the "HTTP Proxy", enter the IP or hostname for the local machine you are running the proxy on, port `8080` then hit "OK".

In the browser you can enter a URL, such as [http://www.apple.com/](http://www.apple.com/), it will make an HTTP request to the proxy to fetch the URL.  The proxy will then request the site, following any redirects, such as HTTP -> HTTPS.  Any errors will be passed along, successful requests will be processed slightly:

* `image/png` and `image/svg` images will be rendered to an `image/gif` before being passed along to the browser.
* The `charset` is removed from the `text/html` MIME type so Netscape will open show the page rather than prompting for a helper to open it.
* Any URLs in `<img src=>` or `<a href=>` tags will be modified so they refer to an HTTP url instead of HTTPS.
* It sticks a `<br>` after each `<tr>...</tr>` so tables look a little better than a big wall of text (Netscape 1.0N only).
* `<style>` and `<script>` tags are removed
* Some HTML common, fancy entities are rewritten as plain text so they show up properly  (Netscape 1.0N only).
* `nokogiri` is used to process the HTML, so any weird things like missing tags will get fixed and passed along.

### Changes

I haven't tried any other old browsers or computers, but hopefully the proxy can be extended to handle other tweaks in the future, please submit PRs if you extend it!

</details>