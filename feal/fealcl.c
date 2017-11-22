/*
 * fealcl.c
 *
 *  Created on: 20.11.2017
 *      Author: Nils
 */

#include "fealcl.h"
#include "cl.h"

#ifdef __WIN32__
#include <windows.h>
#define OPENCL_LIB_NAME "OpenCL.dll"
#else
#include <dlfcn.h>
#define OPENCL_LIB_NAME "libOpenCL.so"
typedef void* HMODULE;
#define LoadLibrary(NAME) dlopen(NAME,0)
#define FreeLibrary(MODULE) dlclose(MODULE)
#define GetProcAddress(MODULE, NAME) dlsym(MODULE, NAME)
#endif

#define LOAD_SYM(NAME) state->cl.NAME = (cl##NAME##_proc)GetProcAddress(cl_lib, "cl"#NAME)
#define CL state->cl

#define INIT_SIZE 128

static const char* CL_SRC =
		"#define v uchar3\n"
		"#define g get_global_id\n"
		"kernel void t(int r,constant read_only const v*p,int m,volatile global int*n,global write_only v*o){"
			"v k=(v)(g(0),g(1),g(2)),t;"
			"while(r)"
				"if(t=k^p[--r],(uchar)(t.x+t.y+1)!=t.z)"
					"return;"
			"r=atomic_inc(n);"
			"if(r<m)"
				"o[r]=k;"
		"}";
/*"uchar Feal_G(uchar k1, uchar k2, uchar k3, uchar u, uchar v){\n"
 "	uchar x = k1 ^ u;\n"
 "	uchar y = k2 ^ v;\n"
 "	uchar m = x + y + 1; // same as mod 256\n"
 "	uchar r = m; // (m>>6) | (m<<2); // roll done outside, once\n"
 "	return r ^ k3;\n"
 "}\n"
 "\n"
 "__kernel void testKeys(int num_pairs, __constant __read_only const uchar* pairs, int max_outs, volatile __global int* num_outs, __global __write_only uchar* out){\n"
 "	uchar k1 = (uchar)get_global_id(0);\n"
 "	uchar k2 = (uchar)get_global_id(1);\n"
 "	uchar k3 = (uchar)get_global_id(2);\n"
 "	for(int i=0; i<num_pairs; i++){\n"
 "		if(Feal_G(k1, k2, k3, pairs[i*3], pairs[i*3+1])!=pairs[i*3+2]) // pairs[i*3+2] needs to be rolled\n"
 "			return;\n"
 "	}\n"
 "	int index = atomic_inc(num_outs);\n"
 "	if(index<max_outs){\n"
 "		out[index*3] = k1;\n"
 "		out[index*3+1] = k2;\n"
 "		out[index*3+2] = k3; // need to be rolled\n"
 "	}\n"
 "}\n";*/

typedef cl_int (CL_API_CALL *clGetPlatformIDs_proc)(cl_uint /* num_entries */,
		cl_platform_id * /* platforms */, cl_uint * /* num_platforms */);

typedef cl_int (CL_API_CALL *clGetDeviceIDs_proc)(cl_platform_id /* platform */,
		cl_device_type /* device_type */, cl_uint /* num_entries */,
		cl_device_id * /* devices */, cl_uint * /* num_devices */);

typedef cl_context (CL_API_CALL *clCreateContext_proc)(
		const cl_context_properties * /* properties */,
		cl_uint /* num_devices */, const cl_device_id * /* devices */,
		void (CL_CALLBACK * /* pfn_notify */)(const char *, const void *,
				size_t, void *), void * /* user_data */,
		cl_int * /* errcode_ret */);

typedef cl_command_queue (CL_API_CALL *clCreateCommandQueue_proc)(
		cl_context /* context */, cl_device_id /* device */,
		cl_command_queue_properties /* properties */,
		cl_int * /* errcode_ret */);

typedef cl_program (CL_API_CALL *clCreateProgramWithSource_proc)(
		cl_context /* context */, cl_uint /* count */,
		const char ** /* strings */, const size_t * /* lengths */,
		cl_int * /* errcode_ret */);

typedef cl_int (CL_API_CALL *clBuildProgram_proc)(cl_program /* program */,
		cl_uint /* num_devices */, const cl_device_id * /* device_list */,
		const char * /* options */,
		void (CL_CALLBACK * /* pfn_notify */)(cl_program /* program */,
				void * /* user_data */), void * /* user_data */);

typedef cl_kernel (CL_API_CALL *clCreateKernel_proc)(cl_program /* program */,
		const char * /* kernel_name */, cl_int * /* errcode_ret */);

typedef cl_mem (CL_API_CALL *clCreateBuffer_proc)(cl_context /* context */,
		cl_mem_flags /* flags */, size_t /* size */, void * /* host_ptr */,
		cl_int * /* errcode_ret */);

typedef cl_int (CL_API_CALL *clSetKernelArg_proc)(cl_kernel /* kernel */,
		cl_uint /* arg_index */, size_t /* arg_size */,
		const void * /* arg_value */);

typedef cl_int (CL_API_CALL *clFlush_proc)(cl_command_queue /* command_queue */);

typedef cl_int (CL_API_CALL *clFinish_proc)(
		cl_command_queue /* command_queue */);

typedef cl_int (CL_API_CALL *clReleaseKernel_proc)(cl_kernel /* kernel */);

typedef cl_int (CL_API_CALL *clReleaseProgram_proc)(cl_program /* program */);

typedef cl_int (CL_API_CALL *clReleaseMemObject_proc)(cl_mem /* memobj */);

typedef cl_int (CL_API_CALL *clReleaseCommandQueue_proc)(
		cl_command_queue /* command_queue */);

typedef cl_int (CL_API_CALL *clReleaseContext_proc)(cl_context /* context */);

typedef cl_int (CL_API_CALL *clEnqueueWriteBuffer_proc)(
		cl_command_queue /* command_queue */, cl_mem /* buffer */,
		cl_bool /* blocking_write */, size_t /* offset */, size_t /* cb */,
		const void * /* ptr */, cl_uint /* num_events_in_wait_list */,
		const cl_event * /* event_wait_list */, cl_event * /* event */);

typedef cl_int (CL_API_CALL *clEnqueueReadBuffer_proc)(
		cl_command_queue /* command_queue */, cl_mem /* buffer */,
		cl_bool /* blocking_read */, size_t /* offset */, size_t /* cb */,
		void * /* ptr */, cl_uint /* num_events_in_wait_list */,
		const cl_event * /* event_wait_list */, cl_event * /* event */);

typedef cl_int (CL_API_CALL *clEnqueueNDRangeKernel_proc)(
		cl_command_queue /* command_queue */, cl_kernel /* kernel */,
		cl_uint /* work_dim */, const size_t * /* global_work_offset */,
		const size_t * /* global_work_size */,
		const size_t * /* local_work_size */,
		cl_uint /* num_events_in_wait_list */,
		const cl_event * /* event_wait_list */, cl_event * /* event */);

typedef struct cl_ifc {
	clGetPlatformIDs_proc GetPlatformIDs;
	clGetDeviceIDs_proc GetDeviceIDs;
	clCreateContext_proc CreateContext;
	clCreateCommandQueue_proc CreateCommandQueue;
	clCreateProgramWithSource_proc CreateProgramWithSource;
	clBuildProgram_proc BuildProgram;
	clCreateKernel_proc CreateKernel;
	clCreateBuffer_proc CreateBuffer;
	clSetKernelArg_proc SetKernelArg;
	clFlush_proc Flush;
	clFinish_proc Finish;
	clReleaseKernel_proc ReleaseKernel;
	clReleaseProgram_proc ReleaseProgram;
	clReleaseMemObject_proc ReleaseMemObject;
	clReleaseCommandQueue_proc ReleaseCommandQueue;
	clReleaseContext_proc ReleaseContext;
	clEnqueueWriteBuffer_proc EnqueueWriteBuffer;
	clEnqueueReadBuffer_proc EnqueueReadBuffer;
	clEnqueueNDRangeKernel_proc EnqueueNDRangeKernel;
} cl_ifc;

static const size_t global_item_size[3] = { 128, 128, 256 };

typedef struct feal_cl_state_ {
	HMODULE cl_lib;
	cl_ifc cl;
	cl_device_id device_id;
	cl_context context;
	cl_command_queue command_queue;
	feal_cl_size_t pairs_size;
	cl_mem pairs_clobj;
	cl_mem num_outs_clpbj;
	feal_cl_size_t out_size;
	cl_mem out_clpbj;

	cl_program program;
	cl_kernel kernel;

	feal_cl_size_t buffer_size;
	cl_uchar4* buffer;
} feal_cl_state_;

feal_cl_state create_feal_cl(void) {
	HMODULE cl_lib;
	cl_int ret;
	cl_uint ret_num_platforms;
	cl_uint ret_num_devices;
	cl_platform_id platform_id;
	feal_cl_state state;

	cl_lib = LoadLibrary(OPENCL_LIB_NAME);
	if (cl_lib == NULL)
		return NULL;

	state = (feal_cl_state) malloc(sizeof(feal_cl_state_));
	if (!state)
		return NULL;

	state->cl_lib = cl_lib;

	LOAD_SYM(GetPlatformIDs);
	LOAD_SYM(GetDeviceIDs);
	LOAD_SYM(CreateContext);
	LOAD_SYM(CreateCommandQueue);
	LOAD_SYM(CreateProgramWithSource);
	LOAD_SYM(BuildProgram);
	LOAD_SYM(CreateKernel);
	LOAD_SYM(CreateBuffer);
	LOAD_SYM(SetKernelArg);
	LOAD_SYM(Flush);
	LOAD_SYM(Finish);
	LOAD_SYM(ReleaseKernel);
	LOAD_SYM(ReleaseProgram);
	LOAD_SYM(ReleaseMemObject);
	LOAD_SYM(ReleaseCommandQueue);
	LOAD_SYM(ReleaseContext);
	LOAD_SYM(EnqueueWriteBuffer);
	LOAD_SYM(EnqueueReadBuffer);
	LOAD_SYM(EnqueueNDRangeKernel);

	ret = CL.GetPlatformIDs(1, &platform_id, &ret_num_platforms);
	ret = CL.GetDeviceIDs(platform_id, CL_DEVICE_TYPE_DEFAULT, 1,
			&state->device_id, &ret_num_devices);

	/* Create OpenCL Context */
	state->context = CL.CreateContext(NULL, 1, &state->device_id, NULL, NULL,
			&ret);

	/* Create command queue */
	state->command_queue = CL.CreateCommandQueue(state->context,
			state->device_id, 0, &ret);

	/* Create kernel program from source file*/
	state->program = CL.CreateProgramWithSource(state->context, 1, &CL_SRC,
			NULL, &ret);
	ret = CL.BuildProgram(state->program, 1, &state->device_id, NULL, NULL,
			NULL);

	/* Create data parallel OpenCL kernel */
	state->kernel = CL.CreateKernel(state->program, "t", &ret);

	state->pairs_size = INIT_SIZE;
	state->pairs_clobj = CL.CreateBuffer(state->context, CL_MEM_READ_ONLY,
			INIT_SIZE * sizeof(cl_uchar4), NULL, &ret);
	state->num_outs_clpbj = CL.CreateBuffer(state->context, CL_MEM_READ_WRITE,
			sizeof(cl_int), NULL, &ret);
	state->out_size = INIT_SIZE;
	state->out_clpbj = CL.CreateBuffer(state->context, CL_MEM_WRITE_ONLY,
			INIT_SIZE * sizeof(cl_uchar4), NULL, &ret);

	ret = CL.SetKernelArg(state->kernel, 1, sizeof(cl_mem),
			(void *) &state->pairs_clobj);
	ret = CL.SetKernelArg(state->kernel, 3, sizeof(cl_mem),
			(void *) &state->num_outs_clpbj);
	ret = CL.SetKernelArg(state->kernel, 4, sizeof(cl_mem),
			(void *) &state->out_clpbj);

	state->buffer_size = INIT_SIZE;
	state->buffer = (cl_uchar4*) malloc(INIT_SIZE * sizeof(cl_uchar4));

	return state;
}

void release_feal_cl(feal_cl_state state) {
	cl_int ret;

	ret = CL.Flush(state->command_queue);
	ret = CL.Finish(state->command_queue);
	ret = CL.ReleaseKernel(state->kernel);
	ret = CL.ReleaseProgram(state->program);
	ret = CL.ReleaseMemObject(state->pairs_clobj);
	ret = CL.ReleaseMemObject(state->num_outs_clpbj);
	ret = CL.ReleaseMemObject(state->out_clpbj);
	ret = CL.ReleaseCommandQueue(state->command_queue);
	ret = CL.ReleaseContext(state->context);
	free(state->buffer);
	FreeLibrary(state->cl_lib);
	free(state);
}

static feal_cl_ubyte ror2(feal_cl_ubyte b) {
	return (b << 6) | (b >> 2);
}

static feal_cl_ubyte rol2(feal_cl_ubyte b) {
	return (b << 2) | (b >> 6);
}

feal_cl_size_t feal_cl_generate_keys(feal_cl_state state,
		feal_cl_size_t num_pairs, feal_cl_plaintext_pair* pairs,
		feal_cl_size_t num_outs, feal_cl_key_pair* outs) {
	cl_int ret;
	cl_int num_out = 0;
	int i;
	feal_cl_size_t max = num_pairs;

	if (max < num_outs)
		max = num_outs;

	if (max > state->buffer_size) {
		free(state->buffer);
		state->buffer_size = max;
		state->buffer = (cl_uchar4*) malloc(max * sizeof(cl_uchar4));
	}

	if (num_pairs > state->pairs_size) {
		ret = CL.ReleaseMemObject(state->pairs_clobj);
		state->pairs_size = num_pairs;
		state->pairs_clobj = CL.CreateBuffer(state->context, CL_MEM_READ_ONLY,
				num_pairs * sizeof(cl_uchar4), NULL, &ret);
		ret = CL.SetKernelArg(state->kernel, 1, sizeof(cl_mem),
				(void *) &state->pairs_clobj);
	}

	if (num_outs > state->out_size) {
		ret = CL.ReleaseMemObject(state->out_clpbj);
		state->out_size = num_outs;
		state->out_clpbj = CL.CreateBuffer(state->context, CL_MEM_WRITE_ONLY,
				num_outs * sizeof(cl_uchar4), NULL, &ret);
		ret = CL.SetKernelArg(state->kernel, 4, sizeof(cl_mem),
				(void *) &state->out_clpbj);
	}

	for (i = 0; i < num_pairs; i++) {
		state->buffer[i].x = pairs[i].u;
		state->buffer[i].y = pairs[i].v;
		state->buffer[i].z = ror2(pairs[i].c);
	}

	/* Copy input data to the memory buffer */
	ret = CL.EnqueueWriteBuffer(state->command_queue, state->pairs_clobj,
			CL_FALSE, 0, num_pairs * sizeof(cl_uchar4), state->buffer, 0, NULL,
			NULL);

	ret = CL.EnqueueWriteBuffer(state->command_queue, state->num_outs_clpbj,
			CL_FALSE, 0, sizeof(cl_int), &num_out, 0, NULL, NULL);

	ret = CL.SetKernelArg(state->kernel, 0, sizeof(cl_int),
			(void *) &num_pairs);
	ret = CL.SetKernelArg(state->kernel, 2, sizeof(cl_int), (void *) &num_outs);

	ret = CL.EnqueueNDRangeKernel(state->command_queue, state->kernel, 3, NULL,
			global_item_size, NULL, 0, NULL, NULL);

	ret = CL.EnqueueReadBuffer(state->command_queue, state->num_outs_clpbj,
			CL_TRUE, 0, sizeof(cl_int), &num_out, 0, NULL, NULL);
	max = num_out;
	if (max > num_outs)
		max = num_outs;
	ret = CL.EnqueueReadBuffer(state->command_queue, state->out_clpbj, CL_TRUE,
			0, max * sizeof(cl_uchar4), state->buffer, 0, NULL, NULL);

	for (i = 0; i < max; i++) {
		outs[i].k1 = state->buffer[i].x;
		outs[i].k2 = state->buffer[i].y;
		outs[i].k3 = rol2(state->buffer[i].z);
	}
	int j=num_out;
	for(i=0; i<num_out && j<num_outs; i++){
		outs[j].k1 = outs[i].k1 | 0b10000000;
		outs[j].k2 = outs[i].k2 | 0b10000000;
		outs[j].k3 = outs[i].k3;
		j++;
		if(j>=num_outs)
			break;
		outs[j].k1 = outs[i].k1 | 0b10000000;
		outs[j].k2 = outs[i].k2;
		outs[j].k3 = outs[i].k3 ^ 0b00000010;
		j++;
		if(j>=num_outs)
			break;
		outs[j].k1 = outs[i].k1;
		outs[j].k2 = outs[i].k2 | 0b10000000;
		outs[j].k3 = outs[i].k3 ^ 0b00000010;
		j++;
	}
	return num_out<<2;
}

