# Regenerate the site's animated demos with VHS (charmbracelet/vhs).
#
# Requires: vhs, ttyd, ffmpeg on PATH. The `sipnab` the tapes drive is BUILT
# FROM THIS TREE -- see BIN below. It is deliberately NOT taken from PATH.
#
# Why: the demos used to render against whatever `sipnab` happened to be
# installed, which silently decoupled the marketing screenshots from the code
# they claim to show. On 2026-08-03 the homepage Search demo still displayed
# `REGIST`, `PUBLIS` and `SUBSCR` -- the Method column truncated to 6 -- even
# though that was fixed in 7378f9c on 2026-07-20 and is covered by
# call_list.rs::method_column_fits_longest_sip_method_below_120_cols. The
# recording made nine minutes after that commit still showed the bug, because
# the installed binary was 0.5.27 while the tree was long past it. A demo that
# can disagree with the code is worse than no demo: it is a screenshot of a
# defect, published as the product.
#
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

# The binary the tapes drive, built from THIS tree. Prepended to PATH for every
# render so `sipnab` inside a tape resolves here and nowhere else.
BINDIR := $(ROOT)/target/release
BIN := $(BINDIR)/sipnab
CRATE_VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' $(ROOT)/Cargo.toml | head -1)

# SIPNAB_BIN=<path> renders against an already-built binary instead of compiling.
# The VERSION CHECK STILL APPLIES -- that is the whole point, and why this is an
# override of the build step and not of the check.
#
# It exists because the render host and the build host need not be the same
# machine. opensips-1, which carries vhs, ttyd and the fonts, has 1 GB of RAM
# and a toolchain below the crate's rust-version, so it cannot build sipnab at
# all; pointing it at the published release artifact for its architecture is the
# only way it can render a truthful demo. A binary that disagrees with
# Cargo.toml is still refused, whatever its provenance.
ifdef SIPNAB_BIN
BIN := $(SIPNAB_BIN)
BINDIR := $(dir $(SIPNAB_BIN))
endif

# Build it if missing or stale, then prove the binary that will render agrees
# with the tree. The check is the point: a version skew here is invisible in
# the output -- it just quietly records an old UI -- so it must fail loudly
# rather than produce a plausible-looking wrong GIF.
.PHONY: check-bin
check-bin:
ifdef SIPNAB_BIN
	@test -x "$(BIN)" || { echo "demos: SIPNAB_BIN=$(BIN) is not executable"; exit 1; }
	@echo "demos: using prebuilt $(BIN) (no cargo build)"
else
	@cd $(ROOT) && cargo build --release --features tui --bin sipnab
endif
	@got=$$("$(BIN)" --version | awk '{print $$2}'); \
	if [ "$$got" != "$(CRATE_VERSION)" ]; then \
		echo "demos: refusing to render -- $(BIN) reports $$got, Cargo.toml says $(CRATE_VERSION)."; \
		echo "       Rendering now would publish a screenshot of code that is not this tree."; \
		exit 1; \
	fi; \
	case "$$("$(BIN)" --version)" in \
		*tui*) ;; \
		*) echo "demos: refusing to render -- $(BIN) has no tui feature; every tape drives the TUI."; exit 1 ;; \
	esac; \
	echo "demos: rendering against $(BIN) ($$got)"

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
$(STATIC)/%.webp: %.tape common.tape check-bin
	cd $(ROOT) && PATH="$(BINDIR):$$PATH" $(VHS) demos/$*.tape
	$(FFMPEG) -y -loglevel error -i $(STATIC)/$*.gif \
		-c:v libwebp_anim -lossless 1 -compression_level 6 -loop 0 $@
	@rm -f $(STATIC)/$*.gif

# The hero tape emits a PNG screenshot (not a GIF), plus a throwaway .gif;
# the screenshot is converted to the WebP still the homepage ships.
hero: hero.tape common.tape check-bin
	cd $(ROOT) && PATH="$(BINDIR):$$PATH" $(VHS) demos/hero.tape
	$(FFMPEG) -y -loglevel error -i $(STATIC)/hero-static.png \
		-c:v libwebp -lossless 1 -compression_level 6 $(STATIC)/hero-static.webp
	@rm -f $(STATIC)/hero-static.png $(CURDIR)/.hero-tmp.gif

clean-tmp:
	@rm -f $(CURDIR)/.hero-tmp.gif
