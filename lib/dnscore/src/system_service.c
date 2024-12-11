/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
 * The YADIFA TM software product is provided under the BSD 3-clause license:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *        * Redistributions of source code must retain the above copyright
 *          notice, this list of conditions and the following disclaimer.
 *        * Redistributions in binary form must reproduce the above copyright
 *          notice, this list of conditions and the following disclaimer in the
 *          documentation and/or other materials provided with the distribution.
 *        * Neither the name of EURid nor the names of its contributors may be
 *          used to endorse or promote products derived from this software
 *          without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/system_service.h"
#include "dnscore/format.h"
#include "dnscore/thread.h"

#if __windows__

#include <winuser.h>

#if DEBUG
// used to wait to attach the debugger to the process, then break into it
static void system_wait_for_debugger_and_break()
{
    while(!IsDebuggerPresent())
    {
        sleep(1);
    }
    DebugBreak();
}
#endif

static char                         *windows_service_name = NULL;
static SERVICE_STATUS                gSvcStatus;
static SERVICE_STATUS_HANDLE         gSvcStatusHandle;
static HANDLE                        ghSvcStopEvent = NULL;

static system_service_entry_point_t *system_service_entry_point = NULL;
static int                           system_service_argc = 0;
static char                        **system_service_argv = NULL;

#define SYSTEM_SERVICE_ERROR 0xe0000001

ya_result system_service_manage(const char *service_name, int operation)
{
    SC_HANDLE schSCManager;
    SC_HANDLE schService;

    if(service_name == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    // Get a handle to the SCM database.

    schSCManager = OpenSCManager(NULL,                   // local computer
                                 NULL,                   // ServicesActive database
                                 SC_MANAGER_ALL_ACCESS); // full access rights

    if(NULL == schSCManager)
    {
        printf("%s: OpenSCManager failed (%d)\n", service_name, GetLastError());
        return ERROR;
    }

    switch(operation)
    {
        case DNSCORE_SERVICE_INSTALL:
        {
            // Create the service

            TCHAR  szPath[PATH_MAX];

            DWORD  szPathSize = sizeof(szPath);
            HANDLE hndl = GetCurrentProcess();

            if(!QueryFullProcessImageName(hndl, 0, szPath, &szPathSize))
            {
                printf("%s: Cannot install service (%d)\n", service_name, GetLastError());
                return ERROR;
            }

            // strncat(szPath, " --service", sizeof(szPath));

            printf("%s: installing service '%s'\n", service_name, szPath);

            schService = CreateService(schSCManager,              // SCM database
                                       service_name,              // name of service
                                       service_name,              // service name to display
                                       SERVICE_ALL_ACCESS,        // desired access
                                       SERVICE_WIN32_OWN_PROCESS, // service type
                                       SERVICE_DEMAND_START,      // start type
                                       SERVICE_ERROR_NORMAL,      // error control type
                                       szPath,                    // path to service's binary
                                       NULL,                      // no load ordering group
                                       NULL,                      // no tag identifier
                                       NULL,                      // no dependencies
                                       NULL,                      // LocalSystem account
                                       NULL);                     // no password

            if(schService == NULL)
            {
                printf("%s: CreateService failed (%d)\n", service_name, GetLastError());
                CloseServiceHandle(schSCManager);
                return ERROR;
            }
            else
            {
                printf("%s: service installed successfully\n", service_name);
            }
            break;
        }
        case DNSCORE_SERVICE_UNINSTALL:
        {
            schService = OpenService(schSCManager, // SCM database
                                     service_name, // name of service
                                     DELETE);      // need delete access

            if(schService == NULL)
            {
                printf("%s: OpenService failed (%d)\n", service_name, GetLastError());
                CloseServiceHandle(schSCManager);
                return ERROR;
            }

            // Delete the service.

            if(!DeleteService(schService))
            {
                printf("%s: DeleteService failed (%d)\n", service_name, GetLastError());
            }
            else
            {
                printf("%s service deleted successfully\n", service_name);
            }

            break;
        }
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);

    return SUCCESS;
}

static VOID system_service_report_event(LPTSTR szFunction)
{
    HANDLE  hEventSource;
    LPCTSTR lpszStrings[2];
    char    buffer[256];

    hEventSource = RegisterEventSource(NULL, windows_service_name);

    if(NULL != hEventSource)
    {
        snformat(buffer, sizeof(buffer), "%s failed: %d", windows_service_name, GetLastError());

        lpszStrings[0] = windows_service_name;
        lpszStrings[1] = buffer;

        ReportEvent(hEventSource,         // event log handle
                    EVENTLOG_ERROR_TYPE,  // event type
                    0,                    // event category
                    SYSTEM_SERVICE_ERROR, // event identifier
                    NULL,                 // no security identifier
                    2,                    // size of lpszStrings array
                    0,                    // no binary data
                    lpszStrings,          // array of strings
                    NULL);                // no binary data

        DeregisterEventSource(hEventSource);
    }
}

static VOID system_service_report_status(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
{
    static DWORD dwCheckPoint = 1;

    // Fill in the SERVICE_STATUS structure.

    gSvcStatus.dwCurrentState = dwCurrentState;
    gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
    gSvcStatus.dwWaitHint = dwWaitHint;

    if(dwCurrentState == SERVICE_START_PENDING)
    {
        gSvcStatus.dwControlsAccepted = 0;
    }
    else
    {
        gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    }

    if((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED))
    {
        gSvcStatus.dwCheckPoint = 0;
    }
    else
    {
        gSvcStatus.dwCheckPoint = dwCheckPoint++;
    }

    // Report the status of the service to the SCM.
    SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
}

// service control handler

static VOID WINAPI system_service_control_handler(DWORD dwCtrl)
{
    // Handle the requested control code.

    FILE *f = fopen("D:/tmp/service-control.txt", "a+");
    fprintf(f, "%x = %u\n", dwCtrl, dwCtrl);
    fclose(f);

    DebugBreak();

    switch(dwCtrl)
    {
        case SERVICE_CONTROL_STOP:
        {
            system_service_report_status(SERVICE_STOP_PENDING, NO_ERROR, 0);

            // Signal the service to stop.
            dnscore_shutdown();

            SetEvent(ghSvcStopEvent);
            // system_service_report_status(gSvcStatus.dwCurrentState, NO_ERROR, 0);

            return;
        }

        case SERVICE_CONTROL_INTERROGATE:
        {
            break;
        }

        default:
        {
            break;
        }
    }
}

static VOID system_service_init(DWORD dwArgc, LPTSTR *lpszArgv)
{
    // TO_DO: Declare and set any required variables.
    //   Be sure to periodically call ReportSvcStatus() with
    //   SERVICE_START_PENDING. If initialization fails, call
    //   ReportSvcStatus with SERVICE_STOPPED.

    // Create an event. The control handler function, SvcCtrlHandler,
    // signals this event when it receives the stop control code.

    ghSvcStopEvent = CreateEvent(NULL,  // default security attributes
                                 true,  // manual reset event
                                 false, // not signaled
                                 NULL); // no name

    if(ghSvcStopEvent == NULL)
    {
        system_service_report_status(SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }

    // Report running status when initialization is complete.

    system_service_report_status(SERVICE_RUNNING, NO_ERROR, 0);

    // TO_DO: Perform work until service stops.

    for(;;)
    {
        // Check whether to stop the service.

        WaitForSingleObject(ghSvcStopEvent, INFINITE);

        system_service_report_status(SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }
}

// entry point

static void *system_service_entry_point_wrapper(void *ignored)
{
    (void)ignored;
    system_service_entry_point(system_service_argc, system_service_argv);
    return NULL;
}

static VOID WINAPI system_service_main(DWORD argc, LPTSTR *argv)
{
    gSvcStatusHandle = RegisterServiceCtrlHandler(windows_service_name, system_service_control_handler);

    if(!gSvcStatusHandle)
    {
        system_service_report_event(TEXT("RegisterServiceCtrlHandler"));
        return;
    }

    thread_t system_service_thread;

    thread_create(&system_service_thread, system_service_entry_point_wrapper, NULL);

    // These SERVICE_STATUS members remain as set here

    gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    gSvcStatus.dwServiceSpecificExitCode = 0;

    // Report initial status to the SCM

    system_service_report_status(SERVICE_START_PENDING, NO_ERROR, 3000);

    // Perform service-specific initialization and work.

    system_service_init(argc, argv);

    void *system_service_thread_return = NULL;
    thread_join(&system_service_thread, &system_service_thread_return);

    system_service_report_status(SERVICE_STOP, NO_ERROR, 0);
}

ya_result system_service_start(const char *service_name, system_service_entry_point_t *entry_point, int argc, char **argv)
{
    if((service_name == NULL) || (entry_point == NULL) || (argv == NULL))
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    if(windows_service_name != NULL)
    {
        return INVALID_STATE_ERROR;
    }

    windows_service_name = strdup(service_name);

    system_service_entry_point = entry_point;
    system_service_argc = argc;
    system_service_argv = argv;

    SERVICE_TABLE_ENTRY DispatchTable[] = {{(char *)service_name, (LPSERVICE_MAIN_FUNCTION)system_service_main}, {NULL, NULL}};

    // This call returns when the service has stopped.
    // The process should simply terminate when the call returns.

    if(!StartServiceCtrlDispatcher(DispatchTable))
    {
        DWORD err = GetLastError();
        if(err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
        {
            // The program isn't running as a service
            return entry_point(argc, argv);
        }
    }

    return 0;
}

void system_service_uninstall(const char *service_name)
{
    SC_HANDLE      schSCManager;
    SC_HANDLE      schService;
    SERVICE_STATUS ssStatus;

    // Get a handle to the SCM database.

    schSCManager = OpenSCManager(NULL,                   // local computer
                                 NULL,                   // ServicesActive database
                                 SC_MANAGER_ALL_ACCESS); // full access rights

    if(NULL == schSCManager)
    {
        printf("OpenSCManager failed (%d)\n", GetLastError());
        return;
    }

    // Get a handle to the service.

    schService = OpenService(schSCManager, // SCM database
                             service_name, // name of service
                             DELETE);      // need delete access

    if(schService == NULL)
    {
        printf("OpenService failed (%d)\n", GetLastError());
        CloseServiceHandle(schSCManager);
        return;
    }

    // Delete the service.

    if(!DeleteService(schService))
    {
        printf("DeleteService failed (%d)\n", GetLastError());
    }
    else
    {
        printf("Service deleted successfully\n");
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}

#else

#error "not supported"

#endif
