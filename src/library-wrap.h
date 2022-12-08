#ifndef LIBRARY_WRAP_H
#define LIBRARY_WRAP_H

#include "first.h"
#include "base.h"
#include <signal.h>

#if defined(HAVE_SYSLOG_H) && defined(WITH_ANDROID_NDK_SYSLOG_INTERCEPT)

#include <stdarg.h>
#include <syslog.h>
#include <android/log.h>

static const char *android_log_tag = "lighttpd";

void openlog(const char *ident, int option, int facility)
{
    android_log_tag = ident;/*(configfile.c passes persistent constant string)*/
    UNUSED(option);
    UNUSED(facility);
}

void closelog(void)
{
}

void syslog(int priority, const char *format, ...)
{
    switch (priority) {
      case LOG_EMERG:   priority = ANDROID_LOG_FATAL; break;
      case LOG_ALERT:   priority = ANDROID_LOG_FATAL; break;
      case LOG_CRIT:    priority = ANDROID_LOG_ERROR; break;
      case LOG_ERR:     priority = ANDROID_LOG_ERROR; break;
      case LOG_WARNING: priority = ANDROID_LOG_WARN;  break;
      case LOG_NOTICE:  priority = ANDROID_LOG_INFO;  break;
      case LOG_INFO:    priority = ANDROID_LOG_INFO;  break;
      case LOG_DEBUG:   priority = ANDROID_LOG_DEBUG; break;
      default:          priority = ANDROID_LOG_ERROR; break;
    }

    va_list ap;
    va_start(ap, format);
    __android_log_vprint(priority, android_log_tag, format, ap);
    va_end(ap);
}

#endif /* HAVE_SYSLOG_H && WITH_ANDROID_NDK_SYSLOG_INTERCEPT */

#define main // To prevent renaming of server_main() into main() in server.c

#ifdef WITH_JAVA_NATIVE_INTERFACE

#include <jni.h>

static void server_status_running (JNIEnv *jenv)
{
    jclass ServerClass = (*jenv)->FindClass(jenv, "com/lighttpd/Server");
    if (ServerClass) {
        jmethodID onLaunchedID = (*jenv)->GetStaticMethodID(
            jenv, ServerClass, "onLaunchedCallback", "()V");
        if (onLaunchedID)
            (*jenv)->CallStaticVoidMethod(jenv, ServerClass, onLaunchedID);
    }
}
#define server_status_running(srv) server_status_running(jenv);

__attribute_cold__
JNIEXPORT jint JNICALL Java_com_lighttpd_Server_launch(
    JNIEnv *jenv,
    jobject thisObject,
    jstring configPath
) {
    UNUSED(thisObject);

    const char * config_path = (*jenv)->GetStringUTFChars(jenv, configPath, 0);
    if (!config_path) return -1;

    optind = 1;
    char *argv[] = { "lighttpd", "-D", "-f", (char*)config_path, NULL };
    int rc = server_main(4, argv, jenv);

    (*jenv)->ReleaseStringUTFChars(jenv, configPath, config_path);
    return rc;
}

__attribute_cold__
JNIEXPORT void JNICALL Java_com_lighttpd_Server_gracefulShutdown(
    JNIEnv *jenv,
    jobject thisObject
) {
    UNUSED(jenv);
    UNUSED(thisObject);
    graceful_shutdown = 1;
}

#define server_main(a,b) server_main(a, b, JNIEnv *jenv)

#else

int server_main(int argc, char ** argv, void (*callback)());

static void server_status_running (void (*callback)())
{
    if (callback) callback();
}
#define server_status_running(srv) server_status_running(callback);

__attribute_cold__
int lighttpd_launch(const char * config_path, void (*callback)()) {
    if (!config_path) return -1;

    optind = 1;
    char *argv[] = { "lighttpd", "-D", "-f", (char*)config_path, NULL };
	return server_main(4, argv, callback);
}

#define server_main(a,b) server_main(a, b, void (*callback)())

void lighttpd_graceful_shutdown() {
  graceful_shutdown = 1;
}

#endif

#endif /* LIBRARY_WRAP_H */
