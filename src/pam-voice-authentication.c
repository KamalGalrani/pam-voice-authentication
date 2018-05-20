#define AUDIO_DEVICE "hw:PCH"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/_pam_types.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#include <syslog.h>
#include <signal.h>
#include <errno.h>

#include <alsa/asoundlib.h>

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_SUCCESS;
}

/* expected hook, this is where custom stuff happens */
static void setcred_free (pam_handle_t *pamh, void *ptr, int err) {
  if (ptr) {
    free (ptr);
  }
}

#define AUTH_RETURN                                                                                \
{                                                                                                  \
  *ret_data = retval;                                                                              \
  pam_set_data(pamh, "unix_setcred_return", (void *) ret_data, setcred_free);                      \
  return retval;                                                                                   \
}

PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
  int retval, *ret_data = NULL;
  pam_syslog(pamh, LOG_DEBUG, "[] pam_sm_authenticate called.");

  /* Get a few bytes so we can pass our return value to
     pam_sm_setcred() and pam_sm_acct_mgmt(). */
  ret_data = malloc(sizeof(int));
  if (!ret_data) {
    pam_syslog(pamh, LOG_CRIT, "[] cannot allocate space for return data!");
    return PAM_BUF_ERR;
  }

/////////////////////////////////////////////////////
/////////////////////////////////////////////////////
/////////////////////////////////////////////////////
  pam_syslog(pamh, LOG_DEBUG, "[] declarations...");
  int err;
  char *buffer;
  int buffer_frames = 128;
  unsigned int rate = 16000;
  snd_pcm_t *capture_handle;
  snd_pcm_hw_params_t *hw_params;
  snd_pcm_format_t format = SND_PCM_FORMAT_S16_LE;
  pam_syslog(pamh, LOG_DEBUG, "[] declarations done...");

  err = snd_pcm_open (&capture_handle, AUDIO_DEVICE, SND_PCM_STREAM_CAPTURE, 0);
  pam_syslog(pamh, LOG_DEBUG, "[] pcm_open done");
  if (err < 0) {
    pam_syslog(pamh, LOG_CRIT, "cannot open audio device %s (%s)\n", AUDIO_DEVICE, snd_strerror (err));
  }

  pam_syslog(pamh, LOG_DEBUG, "audio interface opened\n");

  if ((err = snd_pcm_hw_params_malloc (&hw_params)) < 0) {
    pam_syslog(pamh, LOG_CRIT, "cannot allocate hardware parameter structure (%s)\n", snd_strerror (err));
  }

  pam_syslog(pamh, LOG_DEBUG, "hw_params allocated\n");

  if ((err = snd_pcm_hw_params_any (capture_handle, hw_params)) < 0) {
    pam_syslog(pamh, LOG_CRIT, "cannot initialize hardware parameter structure (%s)\n", snd_strerror (err));
  }

  pam_syslog(pamh, LOG_DEBUG, "hw_params initialized\n");

  if ((err = snd_pcm_hw_params_set_access (capture_handle, hw_params, SND_PCM_ACCESS_RW_INTERLEAVED)) < 0) {
    pam_syslog(pamh, LOG_CRIT, "cannot set access type (%s)\n", snd_strerror (err));
  }

  pam_syslog(pamh, LOG_DEBUG, "hw_params access setted\n");

  if ((err = snd_pcm_hw_params_set_format (capture_handle, hw_params, format)) < 0) {
    pam_syslog(pamh, LOG_CRIT, "cannot set sample format (%s)\n", snd_strerror (err));
  }

  pam_syslog(pamh, LOG_DEBUG, "hw_params format setted\n");

  if ((err = snd_pcm_hw_params_set_rate_near (capture_handle, hw_params, &rate, 0)) < 0) {
    pam_syslog(pamh, LOG_CRIT, "cannot set sample rate (%s)\n", snd_strerror (err));
  }

  pam_syslog(pamh, LOG_DEBUG, "hw_params rate setted\n");

  if ((err = snd_pcm_hw_params_set_channels (capture_handle, hw_params, 1)) < 0) {
    pam_syslog(pamh, LOG_CRIT, "cannot set channel count (%s)\n", snd_strerror (err));
  }

  pam_syslog(pamh, LOG_DEBUG, "hw_params channels setted\n");

  if ((err = snd_pcm_hw_params (capture_handle, hw_params)) < 0) {
    pam_syslog(pamh, LOG_CRIT, "cannot set parameters (%s)\n", snd_strerror (err));
  }

  pam_syslog(pamh, LOG_DEBUG, "hw_params setted\n");

  snd_pcm_hw_params_free (hw_params);

  pam_syslog(pamh, LOG_DEBUG, "hw_params freed\n");

  if ((err = snd_pcm_prepare (capture_handle)) < 0) {
    pam_syslog(pamh, LOG_CRIT, "cannot prepare audio interface for use (%s)\n", snd_strerror (err));
  }

  pam_syslog(pamh, LOG_DEBUG, "audio interface prepared\n");

  buffer = malloc(128 * snd_pcm_format_width(format) / 8 * 2);

  pam_syslog(pamh, LOG_DEBUG, "buffer allocated\n");

  for (int i = 0; i < 10; ++i) {
    if ((err = snd_pcm_readi (capture_handle, buffer, buffer_frames)) != buffer_frames) {
      pam_syslog(pamh, LOG_CRIT, "read from audio interface failed (%d: %s)\n", err, snd_strerror (err));
    }
    pam_syslog(pamh, LOG_DEBUG, "read %d done\n", i);
  }

  free(buffer);

  pam_syslog(pamh, LOG_DEBUG, "buffer freed\n");

  snd_pcm_close (capture_handle);
  pam_syslog(pamh, LOG_DEBUG, "audio interface closed\n");

/////////////////////////////////////////////////////
/////////////////////////////////////////////////////
/////////////////////////////////////////////////////

  retval = PAM_AUTHINFO_UNAVAIL;
  AUTH_RETURN;
}
