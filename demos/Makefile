# Regenerate the site's animated demos with VHS (charmbracelet/vhs).
#
# Requires: vhs, ttyd, ffmpeg on PATH, and `sipnab` (0.5.x) installed on PATH.
# Run from the repo root so tapes resolve tests/pcap-samples/*:
#     make -C demos          # render every demo + the hero still
#     make -C demos 09-detail.gif   # one demo
#     make -C demos clean-tmp       # remove scratch renders
#
# Every tape sources demos/common.tape for a single shared look (theme, font,
# size). Outputs land in website/static/demos/ (the served asset dir).

VHS := vhs
ROOT := $(CURDIR)/..
STATIC := $(ROOT)/website/static/demos

TAPES := 01-intro 02-mark-delta 04-filter \
         07-rtp-cli 08-rtp-tui 09-detail 10-multileg
GIFS := $(addprefix $(STATIC)/,$(addsuffix .gif,$(TAPES)))

.PHONY: all hero clean-tmp
all: $(GIFS) hero

# Each served GIF depends on its tape and the shared style preamble.
$(STATIC)/%.gif: %.tape common.tape
	cd $(ROOT) && $(VHS) demos/$*.tape

# The hero tape emits a PNG screenshot (not a GIF), plus a throwaway .gif.
hero: hero.tape common.tape
	cd $(ROOT) && $(VHS) demos/hero.tape
	@rm -f $(CURDIR)/.hero-tmp.gif

clean-tmp:
	@rm -f $(CURDIR)/.hero-tmp.gif
