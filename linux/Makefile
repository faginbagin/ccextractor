# Comment out the following line if you don't have libpng
HAVE_LIBPNG = true

CPPFLAGS += -DGPAC_CONFIG_LINUX -D_FILE_OFFSET_BITS=64 -I../src/gpacmp4
CFLAGS += -g -Wno-write-strings

ifdef HAVE_LIBPNG
	CFLAGS += -DHAVE_LIBPNG
	LDFLAGS += -lpng
endif

CXXFLAGS = $(CFLAGS)
CC = $(CXX)

bindir = $(HOME)/bin
INSTALL = cp -f -p
INSTALL_PROGRAM = cp -f -p

VPATH = ../src:../src/gpacmp4

src_OBJS = \
	608_helpers.o 608.o 608_sami.o 608_smptett.o 608_srt.o 608_spupng.o \
	708_encoding.o 708.o activity.o asf_functions.o avc_functions.o \
	cc_bitstream.o cc_decoders_common.o ccextractor.o constants.o \
	encoding.o es_functions.o es_userdata.o file_functions.o \
	general_loop.o mp4.o myth.o output.o params_dump.o params.o \
	sequencing.o stream_functions.o telxcc.o timing.o ts_functions.o \
	utility.o xds.o

gpacmp4_OBJS = \
	avc_ext.o avilib.o av_parsers.o base_encoding.o bitstream.o \
	box_code_3gpp.o box_code_apple.o box_code_base.o box_code_isma.o \
	box_code_meta.o box_funcs.o data_map.o desc_private.o descriptors.o \
	error.o gpac_ogg.o hinting.o ipmpx_code.o ipmpx_parse.o \
	isom_intern.o isom_read.o isom_store.o isom_write.o list.o \
	media.o media_odf.o meta.o movie_fragments.o \
	odf_code.o odf_codec.o odf_command.o os_divers.o qos.o sample_descs.o \
	slc.o stbl_read.o stbl_write.o track.o tx3g.o url.o utf.o

.PHONY: all
all: ccextractor

.PHONY: clean
clean:
	rm -f *.o ccextractor

ccextractor: $(src_OBJS) $(gpacmp4_OBJS)

.PHONY: install
install: ccextractor
	$(INSTALL_PROGRAM) ccextractor $(bindir)

