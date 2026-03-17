/*
 * Copyright (c) 2021 Huawei Technologies Co.,Ltd.
 *
 * CM is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * cm_client_api.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_client/cm_client_api.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CM_CLIENT_API_H
#define CM_CLIENT_API_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WIN32
#define CLIENT_API __attribute__ ((visibility ("default")))
#else
#define CLIENT_API __declspec(dllexport)
#endif

typedef enum {
    CM_RES_SUCCESS = 0,
    CM_RES_CANNOT_DO = 1,
    CM_RES_DDB_FAILED = 2,
    CM_RES_VERSION_WRONG = 3,
    CM_RES_CONNECT_ERROR = 4,
    CM_RES_TIMEOUT = 5,
    CM_RES_NO_LOCK_OWNER = 6,
} cm_err_code;

typedef void(*CmNotifyFunc)(void);

/*
* cm client init function, before init success, other interfaces fail to be executed.
* @param [in] instId: resource instance id, set in cm_resource.json
* @param [in] resName: resource name, len need to be shorter than 32
* @param [in] func: callback function, can be NULL
* @return 0: success; -1 failed
*/
CLIENT_API int CmInit(unsigned int instId, const char *resName, CmNotifyFunc func);

/*
* cm client finish function, close all cm_client thread.
* @return
 */
CLIENT_API void __attribute__((destructor)) CmClientFini();

/*
* resource get instances stat list function
* @return: res status list json str
*/
CLIENT_API char *CmGetResStats();

/*
* free res status list json str
* @param [in] resStats: res status list json str
* @return 0: success; -1 failed
*/
CLIENT_API int CmFreeResStats(char *resStats);

/*
* resource get lock from cm
* @return: cm_err_code
 */
CLIENT_API int CmResLock(const char *lockName);

/*
* lock owner unlock from cm
* @return: cm_err_code
 */
CLIENT_API int CmResUnlock(const char *lockName);

/*
* get lock owner's res_instance_id from cm
* @param [in&out] instId: lock owner's instance id
* @return: cm_err_code
 */
CLIENT_API int CmResGetLockOwner(const char *lockName, unsigned int *instId);

/*
* lock owner transfer lock to other instance
* @param [in] instId: new lock owner's instance id
* @return: cm_err_code
 */
CLIENT_API int CmResTransLock(const char *lockName, unsigned int instId);

#ifdef __cplusplus
}
#endif
#endif // CM_CLIENT_API_H
