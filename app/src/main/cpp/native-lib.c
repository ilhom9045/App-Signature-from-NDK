/*

The MIT License (MIT)

Copyright (c) 2018  Dmitrii Kozhevin <kozhevin.dima@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the “Software”), to deal in the Software without
restriction, including without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 */

#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <malloc.h>
#include <jni.h>

#include "path_helper.h"
#include "unzip_helper.h"
#include "pkcs7_helper.h"
#include "md5.h"

#define xstr(s) str(s) //important header
#define str(s) #s //important header

const char *getSignature(JNIEnv *env, jobject context) {
    // Build.VERSION.SDK_INT
    jclass versionClass = (*env)->FindClass(env, "android/os/Build$VERSION");
    jfieldID sdkIntFieldID = (*env)->GetStaticFieldID(env, versionClass, "SDK_INT", "I");
    int sdkInt = (*env)->GetStaticIntField(env, versionClass, sdkIntFieldID);
    // Context
    jclass contextClass = (*env)->FindClass(env, "android/content/Context");
    // Context#getPackageManager()
    jmethodID pmMethod = (*env)->GetMethodID(env, contextClass, "getPackageManager",
                                             "()Landroid/content/pm/PackageManager;");
    jobject pm = (*env)->CallObjectMethod(env, context, pmMethod);
    jclass pmClass = (*env)->GetObjectClass(env, pm);
    // PackageManager#getPackageInfo()
    jmethodID piMethod = (*env)->GetMethodID(env, pmClass, "getPackageInfo",
                                             "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    // Context#getPackageName()
    jmethodID pnMethod = (*env)->GetMethodID(env, contextClass, "getPackageName",
                                             "()Ljava/lang/String;");
    jstring packageName = (jstring) ((*env)->CallObjectMethod(env, context, pnMethod));
    int flags;
    if (sdkInt >= 28) {
        flags = 0x08000000; // PackageManager.GET_SIGNING_CERTIFICATES
    } else {
        flags = 0x00000040; // PackageManager.GET_SIGNATURES
    }
    jobject packageInfo = (*env)->CallObjectMethod(env, pm, piMethod, packageName, flags);
    jclass piClass = (*env)->GetObjectClass(env, packageInfo);
    // PackageInfo#signingInfo.apkContentsSigners | PackageInfo#signatures
    jobjectArray signatures;
    if (sdkInt >= 28) {
        // PackageInfo#signingInfo
        jfieldID signingInfoField = (*env)->GetFieldID(env, piClass, "signingInfo",
                                                       "Landroid/content/pm/SigningInfo;");
        jobject signingInfoObject = (*env)->GetObjectField(env, packageInfo, signingInfoField);
        jclass signingInfoClass = (*env)->GetObjectClass(env, signingInfoObject);
        // SigningInfo#apkContentsSigners
        jmethodID signaturesMethod = (*env)->GetMethodID(env, signingInfoClass,
                                                         "getApkContentsSigners",
                                                         "()[Landroid/content/pm/Signature;");
        jobject signaturesObject = (*env)->CallObjectMethod(env, signingInfoObject,
                                                            signaturesMethod);
        signatures = (jobjectArray) (signaturesObject);
    } else {
        // PackageInfo#signatures
        jfieldID signaturesField = (*env)->GetFieldID(env, piClass, "signatures",
                                                      "[Landroid/content/pm/Signature;");
        jobject signaturesObject = (*env)->GetObjectField(env, packageInfo, signaturesField);
        if ((*env)->IsSameObject(env, signaturesObject, NULL)) {
            return ""; // in case signatures is null
        }
        signatures = (jobjectArray) (signaturesObject);
    }
    // Signature[0]
    jobject firstSignature = (*env)->GetObjectArrayElement(env, signatures, 0);
    jclass signatureClass = (*env)->GetObjectClass(env, firstSignature);
    // PackageInfo#signatures[0].toCharString()
    jmethodID signatureByteMethod = (*env)->GetMethodID(env, signatureClass, "toByteArray", "()[B");
    jobject signatureByteArray = (jobject) (*env)->CallObjectMethod(env, firstSignature,
                                                                    signatureByteMethod);
    // MessageDigest.getInstance("MD5")
    jclass mdClass = (*env)->FindClass(env, "java/security/MessageDigest");
    jmethodID mdMethod = (*env)->GetStaticMethodID(env, mdClass, "getInstance",
                                                   "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jobject md5Object = (*env)->CallStaticObjectMethod(env, mdClass, mdMethod,
                                                       (*env)->NewStringUTF(env, "MD5"));
    // MessageDigest#update
    jmethodID mdUpdateMethod = (*env)->GetMethodID(env, mdClass, "update",
                                                   "([B)V");// The return value of this function is void, write V
    (*env)->CallVoidMethod(env, md5Object, mdUpdateMethod, signatureByteArray);
    // MessageDigest#digest
    jmethodID mdDigestMethod = (*env)->GetMethodID(env, mdClass, "digest", "()[B");
    jobject fingerPrintByteArray = (*env)->CallObjectMethod(env, md5Object, mdDigestMethod);
    // iterate over the bytes and convert to md5 array
    jsize byteArrayLength = (*env)->GetArrayLength(env, fingerPrintByteArray);
    jbyte *fingerPrintByteArrayElements = (*env)->GetByteArrayElements(env, fingerPrintByteArray,
                                                                       JNI_FALSE);
    char *charArray = (char *) fingerPrintByteArrayElements;
    char *md5 = (char *) calloc(2 * byteArrayLength + 1, sizeof(char));
    int k;
    for (k = 0; k < byteArrayLength; k++) {
        sprintf(&md5[2 * k], "%02X", charArray[k]); // Not sure if the cast is needed
    }
    return md5;
}

JNIEXPORT jstring JNICALL
Java_tj_ilhom_appsignature_MainActivity_bytesFromJNI(JNIEnv *env, jobject thiz, jobject context) {
    NSV_LOGI("pathHelperGetPath starts\n");
    char *path = pathHelperGetPath();
    NSV_LOGI("pathHelperGetPath finishes\n");

    if (!path) {
        return NULL;
    }
    NSV_LOGI("pathHelperGetPath result[%s]\n", path);
    NSV_LOGI("unzipHelperGetCertificateDetails starts\n");
    size_t len_in = 0;
    size_t len_out = 0;
    unsigned char *content = unzipHelperGetCertificateDetails(path, &len_in);
    NSV_LOGI("unzipHelperGetCertificateDetails finishes\n");
    if (!content) {
        free(path);
        return NULL;
    }
    NSV_LOGI("pkcs7HelperGetSignature starts\n");

    unsigned char *res = pkcs7HelperGetSignature(content, len_in, &len_out);
    NSV_LOGI("pkcs7HelperGetSignature finishes\n");
    NSV_LOGI("calculating md5\n");
    unsigned char md5sum[16] = {""};
    mbedtls_md5((unsigned const char *) res, len_out, md5sum);
    char md5string[33];
    for (int i = 0; i < 16; ++i) {
        sprintf(&md5string[i * 2], "%02x", (unsigned int) md5sum[i]);
    }
    NSV_LOGI("md5:[%s]\n", md5string);
    free(content);
    free(path);
    pkcs7HelperFree();
    return (*env)->NewStringUTF(env,md5string);
//    return jbArray;

//    const char *md5 = getSignature(env, context);
//    char stringToBeReturned;
//    char build_type = xstr(BUILD_TYPE); //get the value of the variable from grade.build
//    if (build_type == "debug") {
//        strcat(md5, "Yay!! String returned from debug variant!");
//    } else if (build_type == "release") {
//        strcat(md5, "Yay!! String returned from release variant!");
//    }
//    return (*env)->NewStringUTF(env, md5);
}

