#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include "org_apache_log4j_Syslog.h"
#include<syslog.h>
#include<unistd.h>

JNIEXPORT void JNICALL 
Java_org_apache_log4j_Syslog_syslog(JNIEnv *env, jobject obj, jbyteArray msg)
{
	openlog("Syslog Test", LOG_PID, LOG_USER);
	jbyte* by = (jbyte*)(*env)->GetByteArrayElements(env,msg, 0);
	char* message = (char*)by;
	//const char* nativeString = (*env)-> GetStringUTFChars(env,String,0);
	syslog(LOG_DEBUG|LOG_LOCAL2, "msg: %s", message); 
	//(*env)->ReleaseStringUTFChars(env, String,0);
	(*env)->ReleaseByteArrayElements(env, obj,by,0);
	closelog();
	//return NewStringUTF(nativeString);
	
}


/*JNIEXPORT void JNICALL //convert a Java byte [] to a C char buffer
Java_org_apache_log4j_Syslog_syslog(JNIEnv *env, jobject obj, jbyteArray msg)
{
	jbyte* by = (jbyte*)(*env)->GetByteArrayElements(env,msg, 0);
	jsize oldlen = (*env)->GetArrayLength(env,msg);
	char* message = (char*)by; 
	int len = (int) oldlen;
	syslog(LOG_DEBUG|LOG_LOCAL2, "debug: %s", message); 
	syslog(LOG_INFO|LOG_LOCAL2, "info: %s", message);
	//syslog(LOG_NOTICE|LOG_LOCAL2, "notice: %s", message);
	syslog(LOG_WARNING|LOG_LOCAL2, "warning: %s", message);
	syslog(LOG_ERR|LOG_LOCAL2, "error: %s", message);
	//syslog(LOG_CRIT|LOG_LOCAL2, "critical: %s", message);
	syslog(LOG_ALERT|LOG_LOCAL2, "alert: %s", message);
	syslog(LOG_EMERG|LOG_LOCAL2, "emerge: %s", message);
	closelog();
}*/
