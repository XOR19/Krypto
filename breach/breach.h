typedef enum {Req_reset, Guess} MsgType;
typedef enum {Correct, Wrong} RplType;
typedef char Msg[70];
typedef char Rpl[400];

struct Message {
	MsgType Type;
	Msg Guess;
};

struct Reply {
	RplType Type;
	Rpl Data;
	int Len;
};
