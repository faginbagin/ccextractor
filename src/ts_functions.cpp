#include "ccextractor.h"

unsigned char tspacket[188]; // Current packet

struct ts_payload
{
    unsigned char *start; // Payload start
    unsigned length;      // Payload length
    unsigned pesstart;    // PES or PSI start
    unsigned pid;         // Stream PID
    int counter;          // continuity counter
	int transport_error;  // 0 = packet OK, non-zero damaged
};

struct ts_payload payload;
unsigned char *last_pat_payload=NULL;
unsigned last_pat_length = 0;


long capbufsize = 20000;
unsigned char *capbuf = (unsigned char*)malloc(capbufsize);
long capbuflen = 0; // Bytes read in capbuf
unsigned char *haup_capbuf = NULL;
long haup_capbufsize = 0;
long haup_capbuflen = 0; // Bytes read in haup_capbuf

unsigned TS_program_number = 0; // Identifier for current program
unsigned pmtpid = 0; // PID for Program Map Table
unsigned autoprogram =0; // Try to find a stream with captions automatically (no -pn needed)
unsigned cappid = 0; // PID for stream that holds caption information
unsigned forced_cappid = 0; // If 1, never mess with the selected PID
int datastreamtype = -1; // User WANTED stream type (i.e. use the stream that has this type)
unsigned cap_stream_type=UNKNOWNSTREAM; // Stream type for cappid
unsigned forced_streamtype=UNKNOWNSTREAM; // User selected (forced) stream type
unsigned pmt_warning_shown=0; // Only display warning once

struct PAT_entry
{
	unsigned program_number;
	unsigned PMT_PID;
	unsigned char *last_pmt_payload;
	unsigned last_pmt_length;
};

struct PMT_entry
{
	unsigned program_number;
	unsigned PMT_PID;
	unsigned elementary_PID;
	unsigned stream_type;
	unsigned printable_stream_type;
};

// PMTs table
#define TS_PMT_MAP_SIZE 128
static PAT_entry pmt_array[TS_PMT_MAP_SIZE] = { 0 };
static uint16_t pmt_array_length = 0;

// Descriptions for ts stream_type
const char *desc[256];

void init_ts_constants(void)
{
    desc[UNKNOWNSTREAM] = "Unknown";
    desc[VIDEO_MPEG1] = "MPEG-1 video";
    desc[VIDEO_MPEG2] = "MPEG-2 video";
    desc[AUDIO_MPEG1] = "MPEG-1 audio";
    desc[AUDIO_MPEG2] = "MPEG-2 audio";
	desc[MHEG_PACKETS] = "MHEG Packets";
	desc[PRIVATE_TABLE_MPEG2] = "MPEG-2 private table sections";
	desc[PRIVATE_MPEG2] ="MPEG-2 private data";
	desc[MPEG2_ANNEX_A_DSM_CC] = "MPEG-2 Annex A DSM CC";
	desc[ITU_T_H222_1] = "ITU-T Rec. H.222.1";
    desc[AUDIO_AAC] =   "AAC audio";
    desc[VIDEO_MPEG4] = "MPEG-4 video";
    desc[VIDEO_H264] =  "H.264 video";
	desc[PRIVATE_USER_MPEG2] = "MPEG-2 User Private";
    desc[AUDIO_AC3] =   "AC3 audio";
    desc[AUDIO_DTS] =   "DTS audio";
    desc[AUDIO_HDMV_DTS]="HDMV audio";
}


// Return 1 for sucessfully read ts packet
int ts_readpacket(void)
{
    buffered_read(tspacket,188);
    past+=result;
    if (result!=188)
    {
        if (result>0)
            mprint("Premature end of file!\n");
        end_of_file=1;
        return 0;
    }

    int printtsprob = 1;
    while (tspacket[0]!=0x47)
    {
        if (printtsprob)
        {
            mprint ("\nProblem: No TS header mark (filepos=%lld). Received bytes:\n", past);
            dump (DMT_GENERIC_NOTICES, tspacket,4, 0, 0);

            mprint ("Skip forward to the next TS header mark.\n");
            printtsprob = 0;
        }

        unsigned char *tstemp;
        // The amount of bytes read into tspacket
        int tslen = 188;

        // Check for 0x47 in the remaining bytes of tspacket
        tstemp = (unsigned char *) memchr (tspacket+1, 0x47, tslen-1);
        if (tstemp != NULL )
        {
            // Found it
            int atpos = tstemp-tspacket;

            memmove (tspacket,tstemp,(size_t)(tslen-atpos));
            buffered_read(tspacket+(tslen-atpos),atpos);
            past+=result;
            if (result!=atpos) 
            {
                mprint("Premature end of file!\n");
                end_of_file=1;
                return 0;
            }
        }
        else
        {
            // Read the next 188 bytes.
            buffered_read(tspacket,tslen);
            past+=result;
            if (result!=tslen) 
            {
                mprint("Premature end of file!\n");
                end_of_file=1;
                return 0;
            }
        }
    }

    unsigned char *payload_start = tspacket + 4;
    unsigned payload_length = 188 - 4;

    unsigned transport_error_indicator = (tspacket[1]&0x80)>>7;
    unsigned payload_start_indicator = (tspacket[1]&0x40)>>6;
    // unsigned transport_priority = (tspacket[1]&0x20)>>5;
    unsigned pid = (((tspacket[1] & 0x1F) << 8) | tspacket[2]) & 0x1FFF;
    // unsigned transport_scrambling_control = (tspacket[3]&0xC0)>>6;
    unsigned adaptation_field_control = (tspacket[3]&0x30)>>4;
    unsigned ccounter = tspacket[3] & 0xF;

    if (transport_error_indicator)
    {
        mprint ("Warning: Defective (error indicator on) TS packet (filepos=%lld):\n", past);
        dump (DMT_GENERIC_NOTICES, tspacket, 188, 0, 0);
    }

    unsigned adaptation_field_length = 0;
    if ( adaptation_field_control & 2 )
    {
		// Take the PCR (Program Clock Reference) from here, in case PTS is not available (copied from telxcc).
        adaptation_field_length = tspacket[4];

		uint8_t af_pcr_exists = (tspacket[5] & 0x10) >> 4;
			if (af_pcr_exists > 0) {
				uint64_t pts = 0;
				pts |= (tspacket[6] << 25);
				pts |= (tspacket[7] << 17);
				pts |= (tspacket[8] << 9);
				pts |= (tspacket[9] << 1);
				pts |= (tspacket[10] >> 7);
				global_timestamp = (uint32_t) pts / 90;
				pts = ((tspacket[10] & 0x01) << 8);
				pts |= tspacket[11];
				global_timestamp += (uint32_t) (pts / 27000);
				if (!global_timestamp_inited)
				{
					min_global_timestamp = global_timestamp;
					global_timestamp_inited = 1;
				}
			}


        payload_start = payload_start + adaptation_field_length + 1;
        payload_length = tspacket+188-payload_start;
    }

    dbg_print(DMT_PARSE, "TS pid: %d  PES start: %d  counter: %u  payload length: %u  adapt length: %d\n",
            pid, payload_start_indicator, ccounter, payload_length,
            int(adaptation_field_length));

    // Catch bad packages with adaptation_field_length > 184 and
    // the unsigned nature of payload_length leading to huge numbers.
    if (payload_length > 184)
    {
        // This renders the package invalid
        payload_length = 0;
        dbg_print(DMT_PARSE, "  Reject package - set length to zero.\n");
    }

    // Save data in global struct
    payload.start = payload_start;
    payload.length = payload_length;
    payload.pesstart = payload_start_indicator;
    payload.pid = pid;
    payload.counter = ccounter;
	payload.transport_error = transport_error_indicator;
    if (payload_length == 0)
    {
        dbg_print(DMT_PARSE, "  No payload in package.\n");
    }

    // Store packet information
    return 1;
}

unsigned get_printable_stream_type (unsigned stream_type)
{
	unsigned tmp_stream_type=stream_type;	
    switch (stream_type)
    {
		case VIDEO_MPEG2:
		case VIDEO_H264:
		case PRIVATE_MPEG2:
		case MHEG_PACKETS:
		case MPEG2_ANNEX_A_DSM_CC:
		case ITU_T_H222_1:
		case VIDEO_MPEG1:
		case AUDIO_MPEG1:
		case AUDIO_MPEG2:
		case AUDIO_AAC:
		case VIDEO_MPEG4:
		case AUDIO_AC3:
		case AUDIO_DTS:
		case AUDIO_HDMV_DTS:			
			break;
		default:
			if (stream_type>=0x80 && stream_type<=0xFF) 
				tmp_stream_type=PRIVATE_USER_MPEG2;
			else
				tmp_stream_type = UNKNOWNSTREAM;
			break;
    }
	return tmp_stream_type;
}

void clear_PMT_array (void)
{
	for (int i=0;i<pmt_array_length;i++)
		if (pmt_array[i].last_pmt_payload)
		{
			free (pmt_array[i].last_pmt_payload);
			pmt_array[i].last_pmt_payload=NULL;
		}
	pmt_array_length=0;	
}


/* Program Allocation Table. It contains a list of all programs and the
   PIDs of their Program Map Table.
   Returns: gotpes */

int process_PAT (void)
{
	int gotpes=0;
	int is_multiprogram=0;
	static int warning_program_not_found_shown=0;

	/* if ((forced_cappid || telext_mode==TXT_IN_USE) && cap_stream_type!=UNKNOWNSTREAM) // Already know what we need, skip
		return 0;  */

    if (!payload.pesstart)
        // Not the first entry. Ignore it, it should not be here.
        return 0;

    unsigned pointer_field = *(payload.start);
    unsigned char *payload_start = payload.start + pointer_field + 1;
	if (tspacket-payload_start+188<0) // Negative length? Seen it, but impossible
		return 0; 
    unsigned payload_length = tspacket+188-payload_start;
	unsigned section_number = payload_start[6];
    unsigned last_section_number = payload_start[7];
	if (section_number > last_section_number) // Impossible: Defective PAT
	{
		dbg_print(DMT_PAT, "Skipped defective PAT packet, section_number=%u but last_section_number=%u\n", 
			section_number, last_section_number);
		return gotpes;
	}
    if ( last_section_number > 0 )
    {
		dbg_print(DMT_PAT, "Long PAT packet (%u / %u), skipping.\n",
			section_number, last_section_number);
		return gotpes;
        /* fatal(EXIT_BUG_BUG,
              "Sorry, long PATs not yet supported!\n"); */
    }

	if (last_pat_payload!=NULL && payload_length == last_pat_length && 
		!memcmp (payload_start, last_pat_payload, payload_length))
	{
		// dbg_print(DMT_PAT, "PAT hasn't changed, skipping.\n");
		return 0;
	}

	if (last_pat_payload!=NULL)
	{
		mprint ("Notice: PAT changed, clearing all variables.\n");
		clear_PMT_array();
		if (telext_mode==TXT_IN_USE)
			telext_mode=TXT_AUTO_NOT_YET_FOUND;
		cappid=0;
		cap_stream_type=UNKNOWNSTREAM;			
		memset (PIDs_seen,0,sizeof (int) *65536); // Forget all we saw
		if (!tlt_config.user_page) // If the user didn't select a page...
			tlt_config.page=0; // ..forget whatever we detected.

		gotpes=1;
	}

	last_pat_payload=(unsigned char *) realloc (last_pat_payload, payload_length+8); // Extra 8 in case memcpy copies dwords, etc
	if (last_pat_payload==NULL)
		fatal (EXIT_NOT_ENOUGH_MEMORY, "Not enough memory to process PAT.\n");
	memcpy (last_pat_payload, payload_start, payload_length);
	last_pat_length = payload_length;


    unsigned table_id = payload_start[0];
    unsigned section_length = (((payload_start[1] & 0x0F) << 8)
                               | payload_start[2]);
    unsigned transport_stream_id = ((payload_start[3] << 8)
                                    | payload_start[4]);
    unsigned version_number = (payload_start[5] & 0x3E) >> 1;

	// Means current OR next (so you can build a long PAT before it
	// actually is to be in use).
    unsigned current_next_indicator = payload_start[5] & 0x01; 
    


    if (!current_next_indicator)
        // This table is not active, no need to evaluate
        return 0;

    payload_start += 8;
    payload_length = tspacket+188-payload_start;

    unsigned programm_data = section_length - 5 - 4; // prev. bytes and CRC

    dbg_print(DMT_PAT, "Read PAT packet (id: %u) ts-id: 0x%04x\n",
           table_id, transport_stream_id);
    dbg_print(DMT_PAT, "  section length: %u  number: %u  last: %u\n",
           section_length, section_number, last_section_number);
    dbg_print(DMT_PAT, "  version_number: %u  current_next_indicator: %u\n",
           version_number, current_next_indicator);

    if ( programm_data+4 > payload_length )
    {
        fatal(EXIT_BUG_BUG,
              "Sorry, PAT too long!\n");
    }

    unsigned ts_prog_num = 0;
    unsigned ts_prog_map_pid = 0;
    dbg_print(DMT_PAT, "\nProgram association section (PAT)\n");

	int temp=0;
	for( unsigned i=0; i < programm_data; i+=4)
	{
        unsigned program_number = ((payload_start[i] << 8)
			| payload_start[i+1]);
		if( !program_number )
			continue;
		temp++;
		if (temp>=2) // Found 2 programs, we don't need more
			break;
	}

	is_multiprogram = (temp>1); 

    for( unsigned i=0; i < programm_data; i+=4)
    {
        unsigned program_number = ((payload_start[i] << 8)
                                   | payload_start[i+1]);
        unsigned prog_map_pid = ((payload_start[i+2] << 8)
                                 | payload_start[i+3]) & 0x1FFF;

        dbg_print(DMT_PAT, "  Program number: %u  -> PMTPID: %u\n",
                    program_number, prog_map_pid);

		if( !program_number )
			continue;

		if (!is_multiprogram || (ts_forced_program_selected && program_number == ts_forced_program)) 
		{
			// If there's just one program we select it unless the user selected 
			// something else anyway.
			ts_prog_num = program_number;
			ts_prog_map_pid = prog_map_pid;
		}

		// Having an array for PMTs comes from telxcc.
		int found=0,j;
		for (j=0;j<pmt_array_length; j++)
		{
			if (pmt_array[j].program_number == program_number)
			{
				found=1;
				break;
			}
		}
		if (!found && pmt_array_length < TS_PMT_MAP_SIZE)
		{
			pmt_array[pmt_array_length].program_number=program_number;
			pmt_array[pmt_array_length].PMT_PID=prog_map_pid;
			pmt_array_length++;
		}
    } // for 

	if (is_multiprogram && !ts_prog_num)
	{
        // We can only work with "simple" ts files
		if (ts_forced_program_selected && !warning_program_not_found_shown)
		{
			mprint ("\rThe program you selected (%u) wasn't found in the first Program Association Table in the stream.\n",ts_forced_program);
			mprint ("I will continue reading the stream in case the program appears later.\n\n");
			warning_program_not_found_shown=1;
		}
		mprint ("\nThis TS file has more than one program. These are the program numbers found: \n");
		for( unsigned j=0; j < programm_data; j+=4)
		{
			unsigned pn = ((payload_start[j] << 8)
                           | payload_start[j+1]);
			if (pn)
				mprint ("%u\n",pn);
			activity_program_number (pn);
		}
		if (!ts_forced_program_selected)
		{
			if (!autoprogram)
				fatal(EXIT_BUG_BUG, "Run ccextractor again with --program-number specifying which program\nto process.");
			else
				mprint ("\nThe first program with a suitable CC stream will be selected.\n");
		}
	}

    // If we found a new PAT reset all TS stream variables
    if( ts_prog_num != TS_program_number )
    {
        TS_program_number = ts_prog_num;
        pmtpid = ts_prog_map_pid;
		if (!forced_cappid)
			cappid = 0; // Reset caption stream pid
        // If we have data flush it
        if( capbuflen > 0 )        
            gotpes = 1;
    }
	return gotpes;
}

void process_mpeg_descriptor (unsigned char *data, unsigned length)
{
	const char *txt_teletext_type[]={"Reserved", "Initial page", "Subtitle page", "Additional information page", "Programme schedule page", 
		"Subtitle page for hearing impaired people"};
	int i,l;
	if (!data || !length)
		return;
	switch (data[0])
	{
		case ISO639_LANGUAGE:
			if (length<2)
				return;
			l=data[1];
			if (l+2<length)
				return;
			for (i=0;i<l;i+=4)
			{
				char c1=data[i+2], c2=data[i+3], c3=data[i+4];				
				dbg_print(DMT_PMT, "             ISO639: %c%c%c\n",c1>=0x20?c1:' ',
																   c2>=0x20?c2:' ',
																   c3>=0x20?c3:' ');
			}
			break;
		case VBI_DATA_DESCRIPTOR:
			dbg_print(DMT_PMT, "DVB VBI data descriptor (not implemented)\n");
			break;
		case VBI_TELETEXT_DESCRIPTOR:
			dbg_print(DMT_PMT, "DVB VBI teletext descriptor\n");
			break;
		case TELETEXT_DESCRIPTOR:
			dbg_print(DMT_PMT, "             DVB teletext descriptor\n");
			if (length<2)
				return;
			l=data[1];
			if (l+2<length)
				return;
			for (i=0;i<l;i+=5)
			{
				char c1=data[i+2], c2=data[i+3], c3=data[i+4];				
				unsigned teletext_type=(data[i+5]&0xF8)>>3; // 5 MSB
				unsigned magazine_number=data[i+5]&0x7; // 3 LSB
				unsigned teletext_page_number=data[i+6];
				dbg_print (DMT_PMT, "                        ISO639: %c%c%c\n",c1>=0x20?c1:' ',
																   c2>=0x20?c2:' ',
																   c3>=0x20?c3:' ');
				dbg_print (DMT_PMT, "                 Teletext type: %s (%02X)\n", (teletext_type<6? txt_teletext_type[teletext_type]:"Reserved for future use"),
					teletext_type);
				dbg_print (DMT_PMT, "                  Initial page: %02X\n",teletext_page_number);
			}
			break;
		default:
			if (data[0]==REGISTRATION) // Registration descriptor, could be useful eventually
				break;			
			if (data[0]==DATA_STREAM_ALIGNMENT) // Data stream alignment descriptor
				break;
			if (data[0]>=0x13 && data[0]<=0x3F) // Reserved
				break;
			if (data[0]>=0x40 && data[0]<=0xFF) // User private
				break;
			mprint ("Still unsupported MPEG descriptor type=%d (%02X)\n",data[0],data[0]);
			break;
	}
}

/* Process Program Map Table - The PMT contains a list of streams in a program.
   Input: pos => Index in the PAT array    
   Returns: Changes in the selected PID=1, No changes=0, if changes then if the
   buffer had anything it should be flushed.
   PMT specs: ISO13818-1 / table 2-28
   */
int process_PMT (int pos)
{
	int must_flush=0;

	if ((forced_cappid || (telext_mode==TXT_IN_USE && cappid)) && 
		cap_stream_type!=UNKNOWNSTREAM) // Already know what we need, skip
		return 0; 

	if (!payload.pesstart) // Not the first entry. Ignore it, it should not be here.		
		return 0;

    unsigned pointer_field = *(payload.start);
    unsigned char *payload_start = payload.start + pointer_field + 1;
    unsigned payload_length = tspacket+188-payload_start;

	/* We keep a copy of all PMTs, even if not interesting to us for now */
	if (pmt_array[pos].last_pmt_payload!=NULL && payload_length == pmt_array[pos].last_pmt_length && 
		!memcmp (payload_start, pmt_array[pos].last_pmt_payload, payload_length))
	{
		// dbg_print(DMT_PMT, "PMT hasn't changed, skipping.\n");
		return 0;
	}
	pmt_array[pos].last_pmt_payload=(unsigned char *) 
		realloc (pmt_array[pos].last_pmt_payload, payload_length+8); // Extra 8 in case memcpy copies dwords, etc
	if (pmt_array[pos].last_pmt_payload==NULL)
		fatal (EXIT_NOT_ENOUGH_MEMORY, "Not enough memory to process PMT.\n");
	memcpy (pmt_array[pos].last_pmt_payload, payload_start, payload_length);
	pmt_array[pos].last_pmt_length = payload_length;

   
    unsigned table_id = payload_start[0];
    unsigned section_length = (((payload_start[1] & 0x0F) << 8)
                               | payload_start[2]);
    unsigned program_number = ((payload_start[3] << 8)
                               | payload_start[4]);

    unsigned version_number = (payload_start[5] & 0x3E) >> 1;
    unsigned current_next_indicator = payload_start[5] & 0x01;
    if (!current_next_indicator)
        // This table is not active, no need to evaluate
        return 0;
    unsigned section_number = payload_start[6];
    unsigned last_section_number = payload_start[7];
    if ( last_section_number > 0 )
    {
        mprint("Long PMTs are not supported - skipped.\n");
        return 0;
    }
    unsigned PCR_PID = (((payload_start[8] & 0x1F) << 8)
                        | payload_start[9]);
    unsigned pi_length = (((payload_start[10] & 0x0F) << 8)
                          | payload_start[11]);

    if( 12 + pi_length >  payload_length )
    {
        // If we would support long PMTs, this would be wrong.
        mprint("program_info_length cannot be longer than the payload_length - skipped\n");
        return 0;
    }
    payload_start += 12 + pi_length;
    payload_length = tspacket+188-payload_start;

    unsigned stream_data = section_length - 9 - pi_length - 4; // prev. bytes and CRC

    dbg_print(DMT_PARSE, "Read PMT packet  (id: %u) program number: %u\n",
           table_id, program_number);
    dbg_print(DMT_PARSE, "  section length: %u  number: %u  last: %u\n",
           section_length, section_number, last_section_number);
    dbg_print(DMT_PARSE, "  version_number: %u  current_next_indicator: %u\n",
           version_number, current_next_indicator);
    dbg_print(DMT_PARSE, "  PCR_PID: %u  data length: %u  payload_length: %u\n",
           PCR_PID, stream_data, payload_length);

    if (!pmt_warning_shown && stream_data+4 > payload_length )
    {
		dbg_print (DMT_GENERIC_NOTICES, "\rWarning: Probably parsing incomplete PMT, expected data longer than available payload.\n");
		pmt_warning_shown=1;
    }
	dbg_print(DMT_PMT, "\nProgram Map Table for program %u, PMT PID: %u\n",
		program_number,payload.pid);
	// Make a note of the program number for all PIDs, so we can report it later
    for( unsigned i=0; i < stream_data && (i+4)<payload_length; i+=5)
    {
        unsigned stream_type = payload_start[i];
        unsigned elementary_PID = (((payload_start[i+1] & 0x1F) << 8)
                                   | payload_start[i+2]);
        unsigned ES_info_length = (((payload_start[i+3] & 0x0F) << 8)
                                   | payload_start[i+4]);
		if (PIDs_programs[elementary_PID]==NULL)
		{
			PIDs_programs[elementary_PID]=(struct PMT_entry *) malloc (sizeof (struct PMT_entry));
			if (PIDs_programs[elementary_PID]==NULL)
				fatal (EXIT_NOT_ENOUGH_MEMORY, "Not enough memory to process PMT.");
		}
		PIDs_programs[elementary_PID]->elementary_PID=elementary_PID;
		PIDs_programs[elementary_PID]->stream_type=stream_type;
		PIDs_programs[elementary_PID]->program_number=program_number;
		PIDs_programs[elementary_PID]->PMT_PID=payload.pid;		
		PIDs_programs[elementary_PID]->printable_stream_type=get_printable_stream_type (stream_type);
		dbg_print(DMT_PMT, "%6u | %3X (%3u) | %s\n",elementary_PID,stream_type,stream_type,
			desc[PIDs_programs[elementary_PID]->printable_stream_type]);
		process_mpeg_descriptor (payload_start+i+5,ES_info_length);
        i += ES_info_length;
	}
	dbg_print(DMT_PMT, "---\n");
	if (TS_program_number || !autoprogram)
	{
		if( payload.pid != pmtpid) 
		{
			// This isn't the PMT we are interested in (note: If TS_program_number=0 &&
			// autoprogram then we need to check this PMT in case there's a suitable
			// stream)
			return 0; 
		}
		if (program_number != TS_program_number) // Is this the PMT of the program we want?
		{
			// Only use PMTs with matching program number
			dbg_print(DMT_PARSE,"Reject this PMT packet (pid: %u) program number: %u\n",
					   pmtpid, program_number);            
			return 0;
		}
	}

    unsigned newcappid = 0;
    unsigned newcap_stream_type = 0;
    dbg_print(DMT_VERBOSE, "\nProgram map section (PMT)\n");

    for( unsigned i=0; i < stream_data && (i+4)<payload_length; i+=5)
    {
        unsigned stream_type = payload_start[i];
        unsigned elementary_PID = (((payload_start[i+1] & 0x1F) << 8)
                                   | payload_start[i+2]);
        unsigned ES_info_length = (((payload_start[i+3] & 0x0F) << 8)
                                   | payload_start[i+4]);

		if (cappid==0 && stream_type==datastreamtype) // Found a stream with the type the user wants
		{
			forced_cappid=1;
			cappid = newcappid = elementary_PID;
			cap_stream_type=UNKNOWNSTREAM;
		}

		if ((telext_mode==TXT_AUTO_NOT_YET_FOUND || (telext_mode==TXT_IN_USE && !cappid)) // Want teletext but don't know the PID yet
			&& stream_type == PRIVATE_MPEG2) // MPEG-2 Packetized Elementary Stream packets containing private data
		{
			// descriptor_tag: 0x45 = VBI_data_descriptor, 0x46 = VBI_teletext_descriptor, 0x56 = teletext_descriptor
			unsigned descriptor_tag = payload_start[i + 5];
			if ((descriptor_tag == 0x45) || (descriptor_tag == 0x46) || (descriptor_tag == 0x56))
			{
				telxcc_init();
				if (!forced_cappid)
				{
					cappid = newcappid = elementary_PID;
					cap_stream_type = newcap_stream_type = stream_type;
				}
				telext_mode =TXT_IN_USE;						
				mprint ("VBI/teletext stream ID %u (0x%x) for SID %u (0x%x)\n",
					elementary_PID, elementary_PID, program_number, program_number);
			}
		}
		if (telext_mode==TXT_FORBIDDEN && stream_type == PRIVATE_MPEG2) // MPEG-2 Packetized Elementary Stream packets containing private data
		{
			unsigned descriptor_tag = payload_start[i + 5];
			if (descriptor_tag == 0x45)
			{
				cappid = newcappid = elementary_PID;
				cap_stream_type = newcap_stream_type = stream_type;
				mprint ("VBI stream ID %u (0x%x) for SID %u (0x%x) - teletext is disabled, will be processed as closed captions.\n",
					elementary_PID, elementary_PID, program_number, program_number);
			}
		}

		if (forced_cappid && elementary_PID==cappid && cap_stream_type==UNKNOWNSTREAM)
		{
			// We found the user selected CAPPID in PMT. We make a note of its type and don't
			// touch anything else
			if (stream_type>=0x80 && stream_type<=0xFF)
			{
				if (forced_streamtype==UNKNOWNSTREAM)
				{
					mprint ("I can't tell the stream type of the manually selected PID.\n");
					mprint ("Please pass -streamtype to select manually.\n");
					fatal (EXIT_FAILURE, "(user assistance needed)");
				}
				else				
					cap_stream_type = newcap_stream_type = forced_streamtype;
			}
			else
				cap_stream_type = newcap_stream_type = stream_type;
			continue;
		}

		if ((stream_type==VIDEO_H264 || stream_type==VIDEO_MPEG2) 
			&& telext_mode != TXT_IN_USE)
		{
			newcappid = elementary_PID;
			newcap_stream_type = stream_type;
		}

        // For the print command below
        unsigned tmp_stream_type = get_printable_stream_type (stream_type);
        dbg_print(DMT_VERBOSE, "  %s stream [0x%02x]  -  PID: %u\n",
                desc[tmp_stream_type],
                stream_type, elementary_PID);
        i += ES_info_length;
    }
    if (!newcappid && !forced_cappid)
    {
		if (!autoprogram)
		{
			mprint("No supported stream with caption data found, won't be able to process\n");
			mprint("unless a PID is provided manually or packet inspection is enabled.\n");		
		}
		else
		{
			mprint("No supported stream with caption data found in this program.\n");
		}
		return 0;
    }
    if (newcappid != cappid && !forced_cappid)
    {
        cappid = newcappid;
        cap_stream_type = newcap_stream_type;
        mprint ("Decode captions from program %d - %s stream [0x%02x]  -  PID: %u\n",
                program_number , desc[cap_stream_type], cap_stream_type, cappid);
		if (autoprogram) // Make our program selection official
		{
			pmtpid=payload.pid;
			TS_program_number = program_number;
		}
        // If we have data flush it
        if( capbuflen > 0 )            
            must_flush=1;            
    }    

	return must_flush;
}

void look_for_caption_data (void)
{
	// See if we find the usual CC data marker (GA94) in this packet.
	if (payload.length<4 || PIDs_seen[payload.pid]==3) // Second thing means we already inspected this PID
		return;	
	for (unsigned i=0;i<payload.length-3;i++)
	{
		if (payload.start[i]=='G' && payload.start[i+1]=='A' &&
			payload.start[i+2]=='9' && payload.start[i+3]=='4')
		{
			mprint ("PID %u seems to contain captions.\n", payload.pid);
			PIDs_seen[payload.pid]=3;
			return;
		}
	}

}

// Read ts packets until a complete video PES element can be returned.
// The data is read into capbuf and the function returns the number of
// bytes read.
long ts_readstream(void)
{
    static int prev_ccounter = 0;
    static int prev_packet = 0;
    int gotpes = 0;
    long pespcount=0; // count packets in PES with captions
    long pcount=0; // count all packets until PES is complete
    int saw_pesstart = 0;
	int packet_analysis_mode=0; // If we can't find any packet with CC based from PMT, look for captions in all packets
    capbuflen = 0;

    do
    {
        pcount++;

        if( !prev_packet )
        {
            // Exit the loop at EOF
            if ( !ts_readpacket() )
                break;
        }
        else
            prev_packet = 0;

		// Skip damaged packets, they could do more harm than good
		if (payload.transport_error)
		{
			dbg_print(DMT_VERBOSE, "Packet (pid %u) skipped - transport error.\n",
				payload.pid);
            continue;
		}
        // Skip packets with no payload.  This also fixes the problems
        // with the continuity counter not being incremented in empty
        // packets.		
        if ( !payload.length )
        {
			dbg_print(DMT_VERBOSE, "Packet (pid %u) skipped - no payload.\n",
				payload.pid);
            continue;
        }
		
		if (cappid == 0) // We still don't know the PID of the streams with the caption data
		{
            if (!payload.pesstart)
                // Not the first entry. Ignore it, it should not be here.
                continue;
		}

        // Check for PAT
        if( payload.pid == 0) // This is a PAT
        {
			if (process_PAT()) // Returns 1 if there was some data in the buffer already
				capbuflen = 0; 				
            continue;
        }

        // PID != 0 but no PMT selected yet, ignore the rest of the current
        // package and continue searching, UNLESS we are in -autoprogram, which requires us
		// to analyze all PMTs to look for a stream with data.
        if ( !pmtpid && telext_mode!=TXT_IN_USE && !autoprogram)
        {
            dbg_print(DMT_PARSE, "Packet (pid %u) skipped - no PMT pid identified yet.\n",
                       payload.pid);
            continue;
        }

		int is_pmt=0, j;
		for (j=0;j<pmt_array_length;j++)
		{
			if (pmt_array[j].PMT_PID==payload.pid)
			{
				if (!PIDs_seen[payload.pid])
					dbg_print(DMT_PAT, "This PID (%u) is a PMT for program %u.\n",payload.pid, pmt_array[j].program_number);
				is_pmt=1;
				break;
			}
		}

		if (is_pmt)
		{
			PIDs_seen[payload.pid]=2;
			if (process_PMT (j))
				gotpes=1; // Signals that something changed and that we must flush the buffer
			if (payload.pid==pmtpid && cappid==0 && investigate_packets) // It was our PMT yet we don't have a PID to get data from
				packet_analysis_mode=1;

			continue;
		}

		switch (PIDs_seen[payload.pid])
		{
			case 0: // First time we see this PID
				if (PIDs_programs[payload.pid])
				{
					dbg_print(DMT_PARSE, "\nNew PID found: %u (%s), belongs to program: %u\n", payload.pid, 
						desc[PIDs_programs[payload.pid]->printable_stream_type],
						PIDs_programs[payload.pid]->program_number);
					PIDs_seen[payload.pid]=2;
				}
				else
				{
					dbg_print(DMT_PARSE, "\nNew PID found: %u, program number still unknown\n", payload.pid);
					PIDs_seen[payload.pid]=1;
				}
				break;
			case 1: // Saw it before but we didn't know what program it belonged to. Luckier now?
				if (PIDs_programs[payload.pid])
				{
					dbg_print(DMT_PARSE, "\nProgram for PID: %u (previously unknown) is: %u (%s)\n", payload.pid, 
						PIDs_programs[payload.pid]->program_number,
						desc[PIDs_programs[payload.pid]->printable_stream_type]
						);
					PIDs_seen[payload.pid]=2;
				}
				break;
			case 2: // Already seen and reported with correct program
				break;
			case 3: // Already seen, reported, and inspected for CC data (and found some)
				break;
		}


		if (payload.pid==1003 && !hauppauge_warning_shown && !hauppauge_mode) 
		{
			// TODO: Change this very weak test for something more decent such as size.
			mprint ("\n\nNote: This TS could be a recording from a Hauppage card. If no captions are detected, try --hauppauge\n\n");
			hauppauge_warning_shown=1;
		}

        // No caption stream PID defined yet, continue searching.
        if ( !cappid )
        {
			if (!packet_analysis_mode)
				dbg_print(DMT_PARSE, "Packet (pid %u) skipped - no stream with captions identified yet.\n",
                       payload.pid);
			else
				look_for_caption_data ();
            continue;
        }

		if (hauppauge_mode && payload.pid==HAUPPAGE_CCPID)
		{
			// Haup packets processed separately, because we can't mix payloads. So they go in their own buffer
            // copy payload to capbuf
            int haup_newcapbuflen = haup_capbuflen + payload.length;
            if ( haup_newcapbuflen > haup_capbufsize) {
                haup_capbuf = (unsigned char*)realloc(haup_capbuf, haup_newcapbuflen);
                if (!haup_capbuf)
                    fatal(EXIT_NOT_ENOUGH_MEMORY, "Out of memory");
                haup_capbufsize = haup_newcapbuflen;
            }
            memcpy(haup_capbuf+haup_capbuflen, payload.start, payload.length);
            haup_capbuflen = haup_newcapbuflen;

		}

        // Check for PID with captions. Note that in Hauppauge mode we also process the video stream because
		// we need the timing from its PES header, which isn't included in Hauppauge's packets		
		if( payload.pid == cappid)
        {   // Now we got a payload

            // Video PES start
            if (payload.pesstart)
            {
                // Pretend the previous was smaller
                prev_ccounter=payload.counter-1;

                saw_pesstart = 1;
            }

			// Discard packets when no pesstart was found.
            if ( !saw_pesstart )
            {
                dbg_print(DMT_PARSE, "Packet (pid %u) skipped - Did not see pesstart.\n",
                           payload.pid);
                continue;
            }

            // If the buffer is empty we just started this function
            if (payload.pesstart && capbuflen > 0)
            {
                dbg_print(DMT_PARSE, "\nPES finished (%ld bytes/%ld PES packets/%ld total packets)\n",
                           capbuflen, pespcount, pcount);
			
                // Keep the data in capbuf to be worked on

                prev_packet = 1;
                gotpes = 1;
                break;
            }

            if ( (prev_ccounter==15 ? 0 : prev_ccounter+1) != payload.counter )
            {
                mprint("TS continuity counter not incremented prev/curr %u/%u\n",
                       prev_ccounter, payload.counter);
            }
            prev_ccounter = payload.counter;


            pespcount++;
            // copy payload to capbuf
            int newcapbuflen = capbuflen + payload.length;
            if ( newcapbuflen > capbufsize) {
                capbuf = (unsigned char*)realloc(capbuf, newcapbuflen);
                if (!capbuf)
                    fatal(EXIT_NOT_ENOUGH_MEMORY, "Out of memory");
                capbufsize = newcapbuflen;
            }
            memcpy(capbuf+capbuflen, payload.start, payload.length);
            capbuflen = newcapbuflen;
        }
        //else
        //    if(debug_verbose)
        //        printf("Packet (pid %u) skipped - unused.\n",
        //               payload.pid);

        // Nothing suitable found, start over
    }
    while( !gotpes ); // gotpes==1 never arrives here because of the breaks

    return capbuflen;
}


// TS specific data grabber
LLONG ts_getmoredata(void)
{
    long payload_read = 0;
    const char *tstr; // Temporary string to describe the stream type
	
    do
    {
        if( !ts_readstream() )
        {   // If we didn't get data, try again
            mprint("(no CC data extracted)\n");
            continue;
        }
		// Handle obscure case where we didn't find a PMT (so
		// cap_stream_type wasn't set) but the user told us what kind
		// of stream to look for, so we move forward anyway. This
		// happens with MPEG-2 sources from ZeeVee HDbridge.
		if (cap_stream_type == UNKNOWNSTREAM && forced_streamtype != UNKNOWNSTREAM)
		{
			cap_stream_type = forced_streamtype;
		}

        // Separate MPEG-2 and H.264 video streams
        if( cap_stream_type == VIDEO_MPEG2)
        {
            bufferdatatype = PES;
            tstr = "MPG";
        }
        else if( cap_stream_type == VIDEO_H264 )
        {
            bufferdatatype = H264;
            tstr = "H.264";
        }
		else if ( cap_stream_type == UNKNOWNSTREAM && hauppauge_mode)
		{
            bufferdatatype = HAUPPAGE;
            tstr = "Hauppage";
		}
		else if ( cap_stream_type == PRIVATE_MPEG2 && telext_mode==TXT_IN_USE)
		{
            bufferdatatype = TELETEXT;
            tstr = "Teletext";
		}
		else if ( cap_stream_type == PRIVATE_MPEG2 && telext_mode==TXT_FORBIDDEN)
		{
            bufferdatatype = PRIVATE_MPEG2_CC;
            tstr = "CC in private MPEG packet";
		}
		else
		{
			if (forced_cappid)
				fatal (EXIT_UNSUPPORTED, "Unable to determine stream type of selected PID.");
			else
				fatal(EXIT_BUG_BUG, "Not reachable!");
		}
        // We read a video PES

        if (capbuf[0]!=0x00 || capbuf[1]!=0x00 ||
            capbuf[2]!=0x01)
        {
            // ??? Shouldn't happen. Complain and try again.
            mprint("Missing PES header!\n");
            dump(DMT_GENERIC_NOTICES, capbuf,256, 0, 0);
            continue;
        }
        unsigned stream_id = capbuf[3];

		if (telext_mode == TXT_IN_USE)
		{
			if (cappid==0)
			{ // If here, the user forced teletext mode but didn't supply a PID, and we haven't found it yet.
				continue;
			}			
			memcpy(buffer+inbuf, capbuf, capbuflen);
			payload_read = capbuflen;		
			inbuf += capbuflen;
			break;						
		}
		if (bufferdatatype == PRIVATE_MPEG2_CC)
		{
			dump (DMT_GENERIC_NOTICES, capbuf, capbuflen,0, 1);
			// Bogus data, so we return something
				buffer[inbuf++]=0xFA; 
				buffer[inbuf++]=0x80;
				buffer[inbuf++]=0x80;
				payload_read+=3;
			break;
		}
		if (hauppauge_mode)
		{
			if (haup_capbuflen%12 != 0)			
				mprint ("Warning: Inconsistent Hauppage's buffer length\n");
			if (!haup_capbuflen)
			{
				// Do this so that we always return something until EOF. This will be skipped.
				buffer[inbuf++]=0xFA; 
				buffer[inbuf++]=0x80;
				buffer[inbuf++]=0x80;
				payload_read+=3;
			}

			for (int i=0; i<haup_capbuflen; i+=12)
			{
				unsigned haup_stream_id = haup_capbuf[i+3];
				if (haup_stream_id==0xbd && haup_capbuf[i+4]==0 && haup_capbuf[i+5]==6 )
				{
				// Because I (CFS) don't have a lot of samples for this, for now I make sure everything is like the one I have:
				// 12 bytes total length, stream id = 0xbd (Private non-video and non-audio), etc
					if (2 > BUFSIZE - inbuf) 
					{
						fatal(EXIT_BUG_BUG,
							"Remaining buffer (%lld) not enough to hold the 3 Hauppage bytes.\n"
							"Please send bug report!",
							BUFSIZE - inbuf);
					}				
					if (haup_capbuf[i+9]==1 || haup_capbuf[i+9]==2) // Field match. // TODO: If extract==12 this won't work!
					{
						if (haup_capbuf[i+9]==1)
							buffer[inbuf++]=4; // Field 1 + cc_valid=1
						else
							buffer[inbuf++]=5; // Field 2 + cc_valid=1
						buffer[inbuf++]=haup_capbuf[i+10];
						buffer[inbuf++]=haup_capbuf[i+11];			
						payload_read+=3;						
					}							
					/*
					if (inbuf>1024) // Just a way to send the bytes to the decoder from time to time, otherwise the buffer will fill up.
						break;		
					else
						continue; */
				}
			}
			haup_capbuflen=0;			
		}

		if( !((stream_id&0xf0)==0xe0)) // 0xBD = private stream
        {
            // ??? Shouldn't happen. Complain and try again.
            mprint("Not a video PES header!\n");
            continue;
        }

        dbg_print(DMT_VERBOSE, "TS payload start video PES id: %d  len: %ld\n",
               stream_id, capbuflen);

        int pesheaderlen;
        int vpesdatalen = read_video_pes_header(capbuf, &pesheaderlen, capbuflen);

        if (vpesdatalen < 0)
        {   // Seems to be a broken PES
            end_of_file=1;
            break;
        }

        unsigned char *databuf = capbuf + pesheaderlen;
        long databuflen = capbuflen - pesheaderlen;

        // If the package length is unknown vpesdatalen is zero.
        // If we know he package length, use it to quit
        dbg_print(DMT_VERBOSE, "Read PES-%s (databuffer %ld/PES data %d) ",
               tstr, databuflen, vpesdatalen);
        // We got the whole PES in buffer
        if( vpesdatalen && (databuflen >= vpesdatalen) )
            dbg_print(DMT_VERBOSE, " - complete");
        dbg_print(DMT_VERBOSE, "\n");
        

        if (databuflen > BUFSIZE - inbuf)
        {
            fatal(EXIT_BUG_BUG,
                  "PES data packet (%ld) larger than remaining buffer (%lld).\n"
                  "Please send bug report!",
                   databuflen, BUFSIZE - inbuf);
        }

		if (!hauppauge_mode) // in Haup mode the buffer is filled somewhere else
		{
			memcpy(buffer+inbuf, databuf, databuflen);
			payload_read = databuflen;		
			inbuf += databuflen;
		}
        break;
    }
    while ( !end_of_file );

    return payload_read;
}
