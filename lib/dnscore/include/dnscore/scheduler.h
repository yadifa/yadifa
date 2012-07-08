/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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
*------------------------------------------------------------------------------
*
* DOCUMENTATION */
/** @defgroup scheduler Scheduler
 *  @ingroup dnscore
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#ifndef _SCHEDULER_H
#define	_SCHEDULER_H

#include <dnscore/thread_pool.h>

#ifdef	__cplusplus
extern "C"
{
#endif

    /****************************************************************************************************/
    /* SERVER - SIDE API                                                                                */
    /****************************************************************************************************/

    #define SCHEDULER_MAX_TASKS     2048    /* Way too high */
    #define SCHEDULER_MAX_THREADS   1024    /* Way too high */

    /**
     * The return code of a task.
     * If the task returns an error or 'finished', then the next thread is dequeued and started.
     * If it returns 'progress' nothing happens thread-wise.
     */
    #define SCHEDULER_TASK_FINISHED         0
    #define SCHEDULER_TASK_PROGRESS         1
    #define SCHEDULER_TASK_NOTHING          2
    #define SCHEDULER_TASK_DEQUEUE_DELAYED  3

    typedef ya_result scheduler_task_callback(void*);

    int scheduler_init();

    void scheduler_finalize();

    /**
     *
     * n instances
     *
     * Writes a task to the IPC
     * The task will be later processed by calling "scheduler_process"
     */

    void scheduler_schedule_task(scheduler_task_callback* function, void* args);

    /**
     * Queues a thread to be started when the current writer ends.
     *
     * @parm init_function
     * @parm thread_function
     * @parm args
     * @parm categoryname
     */

    void scheduler_schedule_thread(scheduler_task_callback *init_function, thread_pool_function *thread_function, void *args, const char *categoryname);

    /**
     * 1 instance only (main loop)
     *
     * Reads a task from the IPC
     * Enqueue the task to the processing queue
     */
    
    void scheduler_process();

    bool scheduler_has_jobs();

    bool scheduler_task_running();

    /**
     * Do the next job.
     * If there is a job and it fails : returns the error code
     * Else returns either 'progress', 'finished' or 'nothing to do'.
     */

    ya_result scheduler_do_next_job();

    /****************************************************************************************************/

    s32 scheduler_get_running_threads_count();

    /****************************************************************************************************/
    
    void scheduler_print_queue();
    

#ifdef	__cplusplus
}
#endif

#endif	/* _SCHEDULER_H */
/** @} */

/*----------------------------------------------------------------------------*/

