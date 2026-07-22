# Regenerate the site's animated demos with VHS (charmbracelet/vhs).
#
# Requires: vhs, ttyd, ffmpeg on PATH, and `sipnab` (0.5.x) installed on PATH.
# Run from the repo root so tapes resolve tests/pcap-samples/*:
#     make -C demos          # render every demo + the hero still
#     make -C demos 09-detail.webp  # one demo
#     make -C demos clean-tmp       # remove scratch renders
#
# Every tape sources demos/common.tape for a single shared look (theme, font,
# size). Tapes render GIF into website/static/demos/ (VHS can only emit GIF);
# the site ships lossless animated WebP (~30% smaller, pixel-identical), so
# each render is converted and the intermediate GIF removed.

VHS := vhs
FFMPEG := ffmpeg
ROOT := $(CURDIR)/..
STATIC := $(ROOT)/website/static/demos

TAPES := 01-intro 02-mark-delta 04-filter \
         07-rtp-cli 08-rtp-tui 09-detail 10-multileg
WEBPS := $(addprefix $(STATIC)/,$(addsuffix .webp,$(TAPES)))

.PHONY: all hero clean-tmp
all: $(WEBPS) hero

# Each served WebP depends on its tape and the shared style preamble: VHS
# renders the GIF, ffmpeg converts it losslessly, and the GIF goes away.
# NB: the keycast overlay pass (keycast.py, run by hand) draws on the
# intermediate GIF — after overlaying, redo the ffmpeg conversion below so
# the shipped .webp picks up the badges.
$(STATIC)/%.webp: %.tape common.tape
	cd $(ROOT) && $(VHS) demos/$*.tape
	$(FFMPEG) -y -loglevel error -i $(STATIC)/$*.gif \
		-c:v libwebp_anim -lossless 1 -compression_level 6 -loop 0 $@
	@rm -f $(STATIC)/$*.gif

# The hero tape emits a PNG screenshot (not a GIF), plus a throwaway .gif;
# the screenshot is converted to the WebP still the homepage ships.
hero: hero.tape common.tape
	cd $(ROOT) && $(VHS) demos/hero.tape
	$(FFMPEG) -y -loglevel error -i $(STATIC)/hero-static.png \
		-c:v libwebp -lossless 1 -compression_level 6 $(STATIC)/hero-static.webp
	@rm -f $(STATIC)/hero-static.png $(CURDIR)/.hero-tmp.gif

clean-tmp:
	@rm -f $(CURDIR)/.hero-tmp.gif
