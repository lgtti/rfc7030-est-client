#ifndef FEC109FF_C954_4E67_B116_0D574A41ABB1
#define FEC109FF_C954_4E67_B116_0D574A41ABB1

#include "config.h"
#include "types.h"

#define ERROR_SUBSYSTEM_AUTH 			0x1
#define ERROR_SUBSYSTEM_EST 			0x2
#define ERROR_SUBSYSTEM_HTTP 			0x3
#define ERROR_SUBSYSTEM_TLS 			0x4
#define ERROR_SUBSYSTEM_TRANSPORT 		0x5
#define ERROR_SUBSYSTEM_X509 			0x6

/* Define a common EST protocol API error structure. */
typedef struct ESTError {
	/* Subsystem identifier. 
	For the complete list see ERROR_SYBSYSTEM_xxx constants.*/
	int8_t subsystem;

	/* Usually populated using custom error code related to the subsystem. 
	*/
	int16_t code;

	/* Depends by the subsystem field.
		Can be 'errno' value or a specific implementation error code.
	 */
	int native; 

	/* A human description of the error in english form. */
	char human[EST_ERROR_MSG_LEN];
}ESTError_t;

/* Update the input error structure appending the provided message to the current one.
If the total len is greater than the max message len the provided message will be truncated. */
void est_error_update(ESTError_t *err, const char *new_message);

/* Set all fields of the current input error structure using "errno" variable to set the value
of the "native" field. */
void est_error_set(ESTError_t *err, int8_t subsystem, const char *message, int16_t code);

/* Set all fields of the current input error structure leaving the "native" field to zero.
Usually used for business logic error without errno variable value. */
void est_error_set_custom(ESTError_t *err, int8_t subsystem, const char *message, int16_t code);

#endif /* FEC109FF_C954_4E67_B116_0D574A41ABB1 */
