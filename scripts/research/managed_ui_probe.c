/* Read-only Mono UI diagnostics. No managed method invocation or field writes.
 * Only fixed UI object paths, numeric values and UI textures are inspected; no application strings,
 * account objects, tokens, object addresses, or memory dumps are emitted.
 * Built separately and optionally included in debug/jniLibs/arm64-v8a.
 */
#include <jni.h>
typedef unsigned int u32;
typedef unsigned long size_t;
extern int pthread_create(unsigned long *, const void *, void *(*)(void *), void *);
extern int pthread_detach(unsigned long);
extern unsigned int sleep(unsigned int);
struct probe_timespec { long seconds; long nanoseconds; };
extern int clock_gettime(int,struct probe_timespec *);
extern int nanosleep(const struct probe_timespec *,struct probe_timespec *);
extern int strcmp(const char *, const char *);
extern char *strstr(const char *, const char *);
extern char *strchr(const char *, int);
extern void *fopen(const char *, const char *);
extern char *fgets(char *, int, void *);
extern int fclose(void *);
extern int sscanf(const char *, const char *, ...);
extern int memcmp(const void *, const void *, size_t);
extern int snprintf(char *,size_t,const char *,...);
extern int __android_log_print(int, const char *, const char *, ...);
#define LOG(...) __android_log_print(4, "MatrixDiag", __VA_ARGS__)
#define API(ret, name, args) static ret (*name) args
API(void *, mono_get_root_domain, (void));
API(void *, mono_thread_attach, (void *));
API(void, mono_thread_detach, (void *));
API(void, mono_assembly_foreach, (void (*)(void *, void *), void *));
API(void *, mono_assembly_get_image, (void *));
API(const char *, mono_image_get_name, (void *));
API(void *, mono_class_from_name, (void *, const char *, const char *));
API(void *, mono_class_get_field_from_name, (void *, const char *));
API(void *, mono_class_vtable, (void *, void *));
API(void, mono_field_static_get_value, (void *, void *, void *));
API(void, mono_field_get_value, (void *, void *, void *));
API(void *, mono_field_get_value_object, (void *, void *, void *));
API(void *, mono_object_get_class, (void *));
API(void *, mono_class_get_parent, (void *));
API(void *, mono_class_get_fields, (void *, void **));
API(const char *, mono_field_get_name, (void *));
API(void *, mono_field_get_type, (void *));
API(int, mono_type_get_type, (void *));
API(u32, mono_field_get_flags, (void *));
API(u32, mono_gchandle_new, (void *, int));
API(void *, mono_gchandle_get_target, (u32));
API(void, mono_gchandle_free, (u32));
API(void *, mono_profiler_create, (void *));
API(void, mono_profiler_set_exception_throw_callback, (void *, void (*)(void *,void *)));
API(void, mono_stack_walk_no_il, (int (*)(void *,int,int,int,void *),void *));
API(void *, mono_method_get_class, (void *));
API(const char *, mono_method_get_name, (void *));
API(u32, mono_method_get_token, (void *));
API(const char *, mono_class_get_name, (void *));
API(const char *, mono_class_get_namespace, (void *));
API(size_t, mono_array_length, (void *));
API(char *, mono_array_addr_with_size, (void *,int,size_t));

static void *android_image;
static void *mobile_image;
static JavaVM *java_vm;
static jclass diagnostics_class;
static jobject client_context;
static void *exception_profiler;
static unsigned int render_exception_count;
static unsigned int connection_exception_count;
static unsigned int all_exception_count;
static void wait_seconds(unsigned int seconds) {
    // Mono GC signals interrupt sleeps. Use a monotonic deadline, not rounded
    // sleep() remainders that can extend indefinitely under frequent signals.
    struct probe_timespec now;
    if(clock_gettime(1,&now)) return;
    long deadline=now.seconds*1000000000L+now.nanoseconds+(long)seconds*1000000000L;
    for(;;) {
        if(clock_gettime(1,&now)) return;
        long remaining=deadline-now.seconds*1000000000L-now.nanoseconds;
        if(remaining<=0) return;
        struct probe_timespec delay={remaining/1000000000L,remaining%1000000000L};
        nanosleep(&delay,0);
    }
}
struct Trace { void *methods[32]; int offsets[32]; int count; int ui; int connection; };
static int trace_frame(void *method,int native_offset,int il_offset,int managed,void *data) {
    (void)il_offset;(void)managed;
    struct Trace *trace=data;
    if(method) {
        void *klass=mono_method_get_class(method);
        const char *ns=mono_class_get_namespace(klass);
        const char *name=mono_class_get_name(klass);
        const char *method_name=mono_method_get_name(method);
        if(strstr(ns,"Xenko.") || !strcmp(name,"DrawUIContext")) trace->ui=1;
        if(strstr(name,"ConnectToComputer") || strstr(name,"ConnectToPeer") ||
           strstr(name,"ReceivePeerInfo") || strstr(name,"ReceiveMessageAsync") ||
           (!strcmp(ns,"VirtualDesktop.Net") && (strstr(name,"Connect") || strstr(method_name,"Connect")))) trace->connection=1;
        trace->offsets[trace->count]=native_offset;
        trace->methods[trace->count++]=method;
    }
    return trace->count>=32;
}
static void exception_thrown(void *profiler,void *exception) {
    (void)profiler;
    unsigned int ordinal=__atomic_fetch_add(&all_exception_count,1,__ATOMIC_RELAXED);
    if(__atomic_load_n(&render_exception_count,__ATOMIC_RELAXED)>=8 &&
       __atomic_load_n(&connection_exception_count,__ATOMIC_RELAXED)>=24) return;
    struct Trace trace={.count=0,.ui=0,.connection=0};
    mono_stack_walk_no_il(trace_frame,&trace);
    if(trace.connection) {
        if(__atomic_fetch_add(&connection_exception_count,1,__ATOMIC_RELAXED)>=24) return;
    } else {
        if(!trace.ui && ordinal>=3) return;
        if(__atomic_fetch_add(&render_exception_count,1,__ATOMIC_RELAXED)>=8) return;
    }
    void *klass=mono_object_get_class(exception);
    LOG("observed exception render=%d connection=%d %s.%s",trace.ui,trace.connection,mono_class_get_namespace(klass),mono_class_get_name(klass));
    for(int i=0;i<trace.count;i++) {
        klass=mono_method_get_class(trace.methods[i]);
        LOG("exception frame token=%08x nativeOffset=%d %s.%s::%s",mono_method_get_token(trace.methods[i]),trace.offsets[i],mono_class_get_namespace(klass),mono_class_get_name(klass),mono_method_get_name(trace.methods[i]));
    }
}
static void image_callback(void *assembly, void *ignored) {
    (void)ignored;
    void *image = mono_assembly_get_image(assembly);
    if (!strcmp(mono_image_get_name(image), "VirtualDesktop.Android")) android_image = image;
    if (!strcmp(mono_image_get_name(image), "VirtualDesktop.Mobile")) mobile_image = image;
}
static void *field(void *obj, const char *name) {
    if (!obj) return 0;
    for (void *k = mono_object_get_class(obj); k; k = mono_class_get_parent(k)) {
        void *f = mono_class_get_field_from_name(k, name);
        if (f) return f;
    }
    return 0;
}
static void *child(void *obj, const char *name) {
    void *f = field(obj, name), *value = 0;
    if (!f) return 0;
    int type = mono_type_get_type(mono_field_get_type(f));
    if (type != 18 && type != 21 && type != 29) return 0;
    mono_field_get_value(obj, f, &value);
    return value;
}
static int numeric_name(const char *s) {
    if(s[0]=='M' && s[1]>='1' && s[1]<='4' && s[2]>='1' && s[2]<='4' && !s[3]) return 1;
    const char *names[] = {"_isPaused", "_isDisposed", "_isFlyoutControlPanel", "_projectionChanged",
        "_forceDrawAll", "<Opacity>k__BackingField", "_state", "_visible", "visible",
        "isVisible", "_enabled", "enabled", "_isVisible", "_isEnabled", "<Visible>k__BackingField",
        "<Enabled>k__BackingField", "<State>k__BackingField", "<IsMessageVisible>k__BackingField",
        "<IsWarning>k__BackingField", "<IsDirty>k__BackingField", "visibility", "Visibility",
        "<Width>k__BackingField", "<Height>k__BackingField", "<Depth>k__BackingField",
        "<IsMeasureValid>k__BackingField", "<IsArrangeValid>k__BackingField", "opacity", 0};
    for (int i=0; names[i]; i++) if (!strcmp(names[i], s)) return 1;
    const char *geometry[]={"value__","X","Y","Z","W","Width","Height","Radius","CentralAngle","AspectRatio",
        "width","height","isDirty","TextureId","<ViewWidth>k__BackingField","<ViewHeight>k__BackingField",
        "<RenderOpacity>k__BackingField","_hasInputFocus","_isVRStreaming","_hasVRLayer",
        "ImageArrayIndex","LayerFlags","R","G","B","A","drawsQueueCount","isBeginCalled","count","_size","size",0};
    for(int i=0;geometry[i];i++) if(!strcmp(geometry[i],s)) return 1;
    return 0;
}
static void inspect(const char *label, void *obj) {
    LOG("%s present=%d", label, obj != 0);
    if (!obj) return;
    u32 handle=mono_gchandle_new(obj, 1);
    obj=mono_gchandle_get_target(handle);
    for (void *k=mono_object_get_class(obj); k; k=mono_class_get_parent(k)) {
        void *iter=0, *f;
        while ((f=mono_class_get_fields(k, &iter))) {
            const char *name=mono_field_get_name(f);
            if (mono_field_get_flags(f) & 16 || !numeric_name(name)) continue;
            int type=mono_type_get_type(mono_field_get_type(f));
            if (type==2 || type==8 || type==9) {
                int value=0; mono_field_get_value(obj,f,&value);
                LOG("%s.%s=%d",label,name,value);
            } else if (type==12) {
                float value=0; mono_field_get_value(obj,f,&value);
                LOG("%s.%s=%g",label,name,(double)value);
            } else if(type==10 || type==11) {
                long value=0; mono_field_get_value(obj,f,&value);
                LOG("%s.%s=%ld",label,name,value);
            }
        }
    }
    mono_gchandle_free(handle);
}
static void inspect_value(void *domain,const char *label,void *obj,const char *name) {
    void *f=field(obj,name);
    if(!f) { LOG("%s field unavailable",label); return; }
    u32 parent=mono_gchandle_new(obj,1);
    void *v=mono_field_get_value_object(domain,f,mono_gchandle_get_target(parent));
    inspect(label,v);
    mono_gchandle_free(parent);
}
static void inspect_layer(void *domain,const char *label,void *hmd,const char *name,const char *kind) {
    void *f=field(hmd,name);
    if(!f) return;
    void *u=mono_field_get_value_object(domain,f,hmd);
    u32 uh=mono_gchandle_new(u,1);
    void *kf=field(u,kind);
    if(kf) {
        void *v=mono_field_get_value_object(domain,kf,mono_gchandle_get_target(uh));
        u32 vh=mono_gchandle_new(v,1);
        inspect(label,v);
        inspect_value(domain,"layer.type",v,"Type");
        inspect_value(domain,"layer.size",v,"Size");
        inspect_value(domain,"layer.flags",v,"LayerFlags");
        inspect_value(domain,"layer.eye",v,"EyeVisibility");
        void *sf=field(v,"SubImage");
        if(sf) {
            void *sub=mono_field_get_value_object(domain,sf,v);
            u32 sh=mono_gchandle_new(sub,1);
            inspect("layer.subimage",sub);
            inspect_value(domain,"layer.imageRect",sub,"ImageRect");
            mono_gchandle_free(sh);
        }
        void *pf=field(v,"Pose");
        if(pf) {
            void *pose=mono_field_get_value_object(domain,pf,v);
            u32 ph=mono_gchandle_new(pose,1);
            inspect_value(domain,"layer.position",pose,"Position");
            inspect_value(domain,"layer.orientation",pose,"Orientation");
            mono_gchandle_free(ph);
        }
        mono_gchandle_free(vh);
    }
    mono_gchandle_free(uh);
}
static int integer(void *obj,const char *name) {
    void *f=field(obj,name); int value=0;
    if(f && mono_type_get_type(mono_field_get_type(f))==8) mono_field_get_value(obj,f,&value);
    return value;
}
/* Fixed protocol-state fields only. No endpoints, account IDs, keys, proofs,
 * exception messages or arbitrary object traversal are written to the log. */
static void *static_child(void *domain,void *klass,const char *name) {
    void *f=klass ? mono_class_get_field_from_name(klass,name):0,*value=0;
    if(f) {
        int type=mono_type_get_type(mono_field_get_type(f));
        if(type==18 || type==21 || type==29)
            mono_field_static_get_value(mono_class_vtable(domain,klass),f,&value);
    }
    return value;
}
static int static_number(void *domain,void *klass,const char *name) {
    void *f=klass ? mono_class_get_field_from_name(klass,name):0;
    int value=0;
    if(!f) return -1;
    int type=mono_type_get_type(mono_field_get_type(f));
    if(type!=2 && type!=8) return -1;
    mono_field_static_get_value(mono_class_vtable(domain,klass),f,&value);
    return value;
}
static int field_number(void *domain,void *obj,const char *name) {
    void *f=field(obj,name);int value=0;
    if(!f) return -1;
    int type=mono_type_get_type(mono_field_get_type(f));
    if(type==2 || type==8 || type==9) mono_field_get_value(obj,f,&value);
    else if(type==17) {
        void *box=mono_field_get_value_object(domain,f,obj);
        u32 pin=box ? mono_gchandle_new(box,1):0;
        void *underlying=field(box,"value__");
        if(underlying && mono_type_get_type(mono_field_get_type(underlying))==8)
            mono_field_get_value(box,underlying,&value);
        else value=-1;
        if(pin) mono_gchandle_free(pin);
    } else value=-1;
    return value;
}
static void connection_snapshot(void *domain,int seconds) {
    static int previous[12];static int initialized;
    mono_assembly_foreach(image_callback,0);
    if(!mobile_image) return;
    void *klass=mono_class_from_name(mobile_image,"VirtualDesktop.Mobile","NetworkManager");
    if(!klass) return;
    void *computer=static_child(domain,klass,"<Computer>k__BackingField");
    void *client=static_child(domain,klass,"<MessagingClient>k__BackingField");
    u32 computer_pin=computer ? mono_gchandle_new(computer,1):0;
    u32 client_pin=client ? mono_gchandle_new(client,1):0;
    int state[]={static_number(domain,klass,"_connectingToComputer"),
        static_number(domain,klass,"_isConnected"),
        static_number(domain,klass,"_computerUnreachable"),
        static_number(domain,klass,"_computerUnableToConnect"),
        static_number(domain,klass,"<IsComputerRegistryOffline>k__BackingField"),
        field_number(domain,client,"_status"),computer!=0,
        field_number(domain,computer,"<IsOnSameNetwork>k__BackingField"),
        child(computer,"<UdpEndPoint>k__BackingField")!=0,
        field_number(domain,computer,"<Region>k__BackingField"),
        field_number(domain,computer,"<AllowRemoteConnections>k__BackingField"),
        field_number(domain,computer,"<OS>k__BackingField")};
    if(!initialized || memcmp(state,previous,sizeof(state))) {
        LOG("connection snapshot=%d connecting=%d connected=%d unreachable=%d failed=%d registryOffline=%d status=%d computer=%d sameNetwork=%d udpEndpoint=%d region=%d allowRemote=%d os=%d",
            seconds,state[0],state[1],state[2],state[3],state[4],state[5],state[6],state[7],state[8],state[9],state[10],state[11]);
        void *version=child(computer,"<StreamerVersion>k__BackingField");
        u32 version_pin=version ? mono_gchandle_new(version,1):0;
        if(version) LOG("connection peer version=%d.%d.%d.%d",integer(version,"_Major"),integer(version,"_Minor"),integer(version,"_Build"),integer(version,"_Revision"));
        if(version_pin) mono_gchandle_free(version_pin);
        for(int i=0;i<12;i++) previous[i]=state[i];
        initialized=1;
    }
    if(client_pin) mono_gchandle_free(client_pin);
    if(computer_pin) mono_gchandle_free(computer_pin);
}
static void inspect_ui_tree(void *domain,void *obj,int depth,int *nodes) {
    if(!obj || depth>3 || *nodes>=24) return;
    u32 root=mono_gchandle_new(obj,1);
    char label[32];snprintf(label,sizeof(label),"tree.%d",(*nodes)++);
    LOG("%s type=%s depth=%d",label,mono_class_get_name(mono_object_get_class(obj)),depth);
    inspect(label,obj);
    inspect_value(domain,"tree.visibility",obj,"visibility");
    inspect_value(domain,"tree.size",obj,"RenderSizeInternal");
    void *list=child(obj,"<VisualChildrenCollection>k__BackingField");
    int count=integer(list,"size");
    void *items=child(list,"items");
    if(items && count>0 && count<=256 && (size_t)count<=mono_array_length(items)) {
        u32 array=mono_gchandle_new(items,1);
        for(int i=0;i<count && *nodes<24;i++) {
            void *element=*(void **)mono_array_addr_with_size(items,sizeof(void *),(size_t)i);
            inspect_ui_tree(domain,element,depth+1,nodes);
        }
        mono_gchandle_free(array);
    }
    mono_gchandle_free(root);
}
static jobject java_handle(void *obj) {
    void *f=field(obj,"handle"); jobject handle=0;
    if(f && mono_type_get_type(mono_field_get_type(f))==24) mono_field_get_value(obj,f,&handle);
    return handle;
}
static void capture_texture(void *domain,void *klass,void *texture,int mode) {
    void *f=mono_class_get_field_from_name(klass,"_graphicsContext"),*graphics=0;
    if(!f) return;
    mono_field_static_get_value(mono_class_vtable(domain,klass),f,&graphics);
    if(!graphics) return;
    u32 root=mono_gchandle_new(graphics,1);
    void *display=child(graphics,"_display");
    void *context=child(graphics,"<Context>k__BackingField");
    jobject jd=java_handle(display),jc=java_handle(context);
    int id=integer(texture,"TextureId"),w=integer(texture,"<ViewWidth>k__BackingField"),h=integer(texture,"<ViewHeight>k__BackingField");
    if(jd && jc && id && w && h) {
        JNIEnv *env=0;
        if((*java_vm)->AttachCurrentThread(java_vm,(void **)&env,0)==JNI_OK) {
            jmethodID method=(*env)->GetStaticMethodID(env,diagnostics_class,"captureTexture",
                "(Landroid/content/Context;Landroid/opengl/EGLDisplay;Landroid/opengl/EGLContext;IIII)V");
            if(method) (*env)->CallStaticVoidMethod(env,diagnostics_class,method,client_context,jd,jc,id,w,h,mode);
            if((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); LOG("UI capture JNI failed"); }
            (*java_vm)->DetachCurrentThread(java_vm);
        }
    } else LOG("UI capture prerequisites display=%d context=%d texture=%d width=%d height=%d",jd!=0,jc!=0,id!=0,w,h);
    mono_gchandle_free(root);
}
static void snapshot(void *domain, int seconds) {
    mono_assembly_foreach(image_callback, 0);
    if (!android_image) { LOG("snapshot=%d assembly unavailable",seconds); return; }
    void *klass=mono_class_from_name(android_image,"VirtualDesktop","VrApp");
    void *f=klass ? mono_class_get_field_from_name(klass,"_game") : 0;
    if (!f) { LOG("snapshot=%d game field unavailable",seconds); return; }
    void *game=0;
    mono_field_static_get_value(mono_class_vtable(domain,klass),f,&game);
    if (!game) { LOG("snapshot=%d game unavailable",seconds); return; }
    u32 handle=mono_gchandle_new(game,1);
    game=mono_gchandle_get_target(handle);
    LOG("snapshot=%d",seconds);
    LOG("exception callbacks=%u",__atomic_load_n(&all_exception_count,__ATOMIC_RELAXED));
    inspect("game",game);
    inspect("systems",child(game,"<GameSystems>k__BackingField"));
    void *panel=child(game,"<ControlPanel>k__BackingField");
    inspect("panel",panel);
    inspect("grid",child(panel,"_gridMain"));
    inspect("root",child(panel,"_rootElement"));
    inspect("root.children",child(child(panel,"_rootElement"),"<VisualChildrenCollection>k__BackingField"));
    inspect_value(domain,"root.visibility",child(panel,"_rootElement"),"visibility");
    inspect_value(domain,"root.bounds",child(panel,"_rootElement"),"<Bounds>k__BackingField");
    inspect_value(domain,"root.renderSize",child(panel,"_rootElement"),"RenderSizeInternal");
    inspect_value(domain,"panel.resolution",panel,"_realResolution");
    inspect_value(domain,"panel.virtualResolution",panel,"_virtualResolution");
    inspect_value(domain,"panel.world",panel,"_worldMatrix");
    inspect("context",child(panel,"_renderingContext"));
    if(seconds==10) {
        inspect_value(domain,"ui.projection",child(panel,"_renderingContext"),"ViewProjectionMatrix");
        inspect_value(domain,"ui.rootWorld",child(panel,"_rootElement"),"WorldMatrixInternal");
        int nodes=0;inspect_ui_tree(domain,child(panel,"_rootElement"),0,&nodes);
    }
    inspect("texture",child(child(panel,"_renderingContext"),"<RenderTarget>k__BackingField"));
    inspect("video",child(game,"<VideoPlayer>k__BackingField"));
    inspect("screen",child(game,"<Screen>k__BackingField"));
    inspect_value(domain,"screen.center",child(game,"<Screen>k__BackingField"),"Center");
    void *hmd=child(game,"<Hmd>k__BackingField");
    inspect("hmd",hmd);
    inspect_layer(domain,"quad",hmd,"_quadLayer","Quad");
    inspect_layer(domain,"cylinder",hmd,"_cylinderLayer","Cylinder");
    void *batch=child(child(panel,"_uiSystem"),"<Batch>k__BackingField");
    inspect("ui.batch",batch);
    inspect("ui.whiteTexture",child(batch,"whiteTexture"));
    capture_texture(domain,klass,child(child(panel,"_renderingContext"),"<RenderTarget>k__BackingField"),0);
    capture_texture(domain,klass,child(batch,"whiteTexture"),1);
    mono_gchandle_free(handle);
}
static void *worker(void *ignored) {
    (void)ignored;
    unsigned long base=0;
    {
        // The driver has a different linker namespace. Do not dlopen Mono:
        // that can load an uninitialized second runtime. Locate the existing,
        // build-id-verified image and its pinned public API exports instead.
        void *maps=fopen("/proc/self/maps","r");
        char line[2048];
        if (maps) {
            while (fgets(line,sizeof(line),maps)) {
                if (!strstr(line,"/libmonosgen-2.0.so")) continue;
                unsigned long start=0,end=0,offset=1; char flags[5];
                if (sscanf(line,"%lx-%lx %4s %lx",&start,&end,flags,&offset)!=4 ||
                    offset || flags[0]!='r' || end-start<4096) continue;
                if (memcmp((void *)(start+probe_build_id_offset),probe_build_id,sizeof(probe_build_id))) continue;
                base=start; break;
            }
            fclose(maps);
        }
    }
    if (!base) { LOG("pinned Mono image unavailable"); return 0; }
#define LOAD(name) name=(void *)(base+probe_export_##name)
    LOAD(mono_get_root_domain); LOAD(mono_thread_attach); LOAD(mono_thread_detach);
    LOAD(mono_assembly_foreach); LOAD(mono_assembly_get_image); LOAD(mono_image_get_name);
    LOAD(mono_class_from_name); LOAD(mono_class_get_field_from_name); LOAD(mono_class_vtable);
    LOAD(mono_field_static_get_value); LOAD(mono_field_get_value); LOAD(mono_object_get_class);
    LOAD(mono_field_get_value_object);
    LOAD(mono_class_get_parent); LOAD(mono_class_get_fields); LOAD(mono_field_get_name);
    LOAD(mono_field_get_type); LOAD(mono_type_get_type); LOAD(mono_field_get_flags);
    LOAD(mono_gchandle_new); LOAD(mono_gchandle_get_target); LOAD(mono_gchandle_free);
    LOAD(mono_profiler_create);LOAD(mono_profiler_set_exception_throw_callback);
    LOAD(mono_stack_walk_no_il);LOAD(mono_method_get_class);LOAD(mono_method_get_name);LOAD(mono_method_get_token);
    LOAD(mono_class_get_name);LOAD(mono_class_get_namespace);
    LOAD(mono_array_length);LOAD(mono_array_addr_with_size);
    void *domain=mono_get_root_domain();
    if (!domain) { LOG("domain unavailable"); return 0; }
    exception_profiler=mono_profiler_create(0);
    mono_profiler_set_exception_throw_callback(exception_profiler,exception_thrown);
    LOG("render and connection exception observation active");
    // Short reads once per second, emitting only changed protocol state.
    for(int seconds=1;seconds<=300;seconds++) {
        wait_seconds(1);
        void *thread=mono_thread_attach(domain);
        connection_snapshot(domain,seconds);
        if(seconds==10 || seconds==30 || seconds==60) snapshot(domain,seconds);
        mono_thread_detach(thread);
    }
    mono_profiler_set_exception_throw_callback(exception_profiler,0);
    JNIEnv *env=0;
    if((*java_vm)->AttachCurrentThread(java_vm,(void **)&env,0)==JNI_OK) {
        (*env)->DeleteGlobalRef(env,diagnostics_class);
        (*env)->DeleteGlobalRef(env,client_context);
        (*java_vm)->DetachCurrentThread(java_vm);
    }
    LOG("UI snapshots complete");
    return 0;
}
__attribute__((visibility("default")))
void Java_org_picomatrix_bridge_RuntimeDiagnostics_startNative(JNIEnv *env, jclass klass, jobject client) {
    if((*env)->GetJavaVM(env,&java_vm)!=JNI_OK) return;
    diagnostics_class=(*env)->NewGlobalRef(env,klass);
    client_context=(*env)->NewGlobalRef(env,client);
    unsigned long thread;
    if (!pthread_create(&thread,0,worker,0)) pthread_detach(thread);
}
