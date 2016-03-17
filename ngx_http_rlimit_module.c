#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define HASH_SIZE 256
#define HASH_BITS 0xff
#define REPORT_MASK 0x7fff
#define MINPOOLSIZE 1024*1024
#define MAX_WHITES 16
#define MAX_URI_LEN 256
#define MAX_NODE_HITWEIGHT 1024
#define VERSION	"0.8-6"

typedef struct {
    in_addr_t addr;
    in_addr_t mask;
} in_addr_s;

typedef struct {
    ngx_shm_zone_t *shm_zone;
} ngx_http_rlimit_loc_conf_t;

typedef struct rlimit_node {
    struct rlimit_node *next;
    unsigned long	ip;
    ngx_int_t	hits;
    ngx_int_t	burst;
    time_t	ts;
    time_t	bts;
    time_t	bantill;
    char *	uri;
    ngx_uint_t  ulen;
    ngx_int_t	hitweight;
} rlimit_node_t;

typedef struct {
    ngx_int_t	hits;
    ngx_int_t	nodes;
    ngx_int_t	run;
    ngx_int_t	old;
    ngx_int_t	np;
} rlimit_stats_t;

typedef struct {
    ngx_int_t requests_total;
    time_t time_total;
    ngx_int_t requests_burst;
    time_t time_burst;
    time_t bantime;
    ngx_int_t log;
    ngx_int_t internal_off;
    ngx_int_t check_url;
    in_addr_s whites[MAX_WHITES];
    ngx_int_t error_code;
} rlimit_conf_t;    

typedef struct {
    /* pointers to table rows */
    rlimit_node_t ** hash_heads;
    /* pointers to mutexes */
    ngx_shmtx_t *hash_locks;
    /* statistics */
    rlimit_stats_t * stats;
    /* pool config */
    rlimit_conf_t conf;
} ngx_http_rlimit_ctx_t;

static ngx_int_t ngx_http_rlimit_handler(ngx_http_request_t *r);
static void *ngx_http_rlimit_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_rlimit_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_rlimit_init(ngx_conf_t *cf);

static char *ngx_http_rlimit_create_pool(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_rlimit_attach_pool(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_rlimit_parse_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_http_rlimit_commands[] = {
    { ngx_string("rlimit"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE2,
      ngx_http_rlimit_create_pool,
      NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("rlimit_pool"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_rlimit_attach_pool,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_rlimit_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_rlimit_init,           /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_rlimit_create_loc_conf,   /* create location configuration */
    ngx_http_rlimit_merge_loc_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_rlimit_module = {
    NGX_MODULE_V1,
    &ngx_http_rlimit_module_ctx,       /* module context */
    ngx_http_rlimit_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static inline ngx_int_t rlimit_hash_key(unsigned long addr, unsigned long mask) {
    return ((addr ^ (addr >> 2) ^ (addr >> 6)) & mask);
}


static inline ngx_int_t kukluxklan(in_addr_s * whites, unsigned long suspicious) {
	int i;
	
	for(i=0; i<MAX_WHITES; i++) {
		if (!(whites[i].addr))
			break;
		if (whites[i].addr == (suspicious & whites[i].mask))
			return 1;
	}
	
	/* cross burning */
	return 0;
}

static rlimit_node_t * rlimit_node_alloc(rlimit_conf_t *cf, ngx_slab_pool_t * shpool, in_addr_t addr, time_t now, ngx_str_t *uri) {
    rlimit_node_t * node;
    int ulen;	
    
    node = ngx_slab_alloc(shpool, sizeof(rlimit_node_t));
    if (node == NULL)
	return NULL;
	
    if (cf->check_url) {
    	ulen = uri->len > MAX_URI_LEN ? MAX_URI_LEN : uri->len;
    	node->uri = ngx_slab_alloc(shpool, ulen);
    	if (node->uri == NULL) {
		ngx_slab_free(shpool, node);
		return NULL;
    	}
    
	memcpy(node->uri, uri->data, ulen);
	node->ulen = ulen;
    }

    node->ip = addr;
    node->ts = node->bts = now;
    node->hits = node->burst = 1;
    node->hitweight = 1;

    return node;
}

static ngx_int_t rlimit_check_node(rlimit_conf_t * cf, rlimit_node_t * node, time_t now, ngx_http_request_t *r) {
    ngx_int_t bursts;

    /* cleanup burst time counter */
    if (cf->requests_burst && (now - node->bts > cf->time_burst)) {
	node->burst = 0;
	node->bts = now;
    }
    
    /* cleanup total time counter */
    if (cf->requests_total && (now - node->ts > cf->time_total)) {
	node->hits = 0;
	node->ts = now;
	node->hitweight = 1;
    }
    
    bursts = node->burst;
    node->hits += node->hitweight;
    node->burst += node->hitweight;
    
    /* ban on total overflow */
    if (cf->requests_total && (node->hits > cf->requests_total)) {
	node->bantill = now + cf->bantime;
	if (cf->log > 0) ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "rlimit_module-%s: %08XD BANNED! (%d-%d)", VERSION, node->ip, node->hits, node->hitweight);
	goto rlimit_check_no;
    }
    
    /* if burst limit exceeded just 500, no ban */
    if (cf->requests_burst && (node->burst > cf->requests_burst)) {
	if ((cf->log > 1) && (bursts <= cf->requests_burst))
	    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "rlimit_module-%s: %08XD bursted (%d+%d=%d)", VERSION, node->ip, bursts, node->hitweight, node->burst);
	goto rlimit_check_no;
    }
    
    return NGX_DECLINED;
    
rlimit_check_no:
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}
 

static ngx_int_t rlimit_check_url(ngx_http_request_t *r, ngx_slab_pool_t *shpool, rlimit_node_t *node) {
    ngx_int_t ulen;
    
    if (!node->uri) {
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "rlimit_module-%s: rlimit_check_url: >>> INVALID NODE! <<<", VERSION);
	return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    /* check url hit */
    /* if request_line > MAX_URI_LEN or request_line.len == node->ulen then check. else reallocate */ 
    if ( ((r->request_line.len >= MAX_URI_LEN) && (node->ulen == MAX_URI_LEN)) || (r->request_line.len == node->ulen) ) { 
	ulen = node->ulen;
	if (memcmp(node->uri, r->request_line.data, ulen)) {
	    /* miss - reset hitweight */
	    node->hitweight = 1;
	    memcpy(node->uri, r->request_line.data, ulen);
	}
	else {
	    /* hit - double  weight */
	    node->hitweight *= 2;
	    if (node->hitweight > MAX_NODE_HITWEIGHT) node->hitweight = MAX_NODE_HITWEIGHT;
	}
    }
    else {
	/* miss - reset hitweight */
	node->hitweight = 1;
	
	/* reallocate uri */
	ulen = r->request_line.len > MAX_URI_LEN ? MAX_URI_LEN : r->request_line.len;
	ngx_slab_free(shpool, node->uri);
	node->uri = ngx_slab_alloc(shpool, ulen);
	
	if (node->uri == NULL) {
	    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "rlimit_module-%s: rlimit_check_url: >>> OUT OF MEMORY REALLOCATING URL! <<<", VERSION);
	    return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	    
	memcpy(node->uri, r->request_line.data, ulen);
	node->ulen = ulen;
    }

    return NGX_OK;
}


static ngx_int_t ngx_http_rlimit_handler(ngx_http_request_t *r) {
    time_t now;
    in_addr_t addr;
    rlimit_node_t *node, *head, *prev=NULL;
    ngx_slab_pool_t * shpool;
    ngx_int_t key, ret=NGX_DECLINED;
    ngx_http_rlimit_ctx_t * ctx;
    ngx_http_rlimit_loc_conf_t * rlcf = ngx_http_get_module_loc_conf(r, ngx_http_rlimit_module);
    rlimit_stats_t * stats;
    rlimit_conf_t cf;
    time_t life;
    
    if (rlcf->shm_zone == NULL)
	return NGX_DECLINED;

    /* init variables */
    shpool = (ngx_slab_pool_t *) rlcf->shm_zone->shm.addr;

    ctx = rlcf->shm_zone->data;
    cf = ctx->conf;

    if (cf.internal_off &&  r->internal)
	return NGX_DECLINED;

    /* get address and check if white */
    addr = ((struct sockaddr_in *) (r->connection->sockaddr))->sin_addr.s_addr;
    if (kukluxklan(cf.whites, addr))
	return NGX_DECLINED;
    
    stats = ctx->stats;

    now = ngx_time();
    key = rlimit_hash_key(addr, HASH_BITS);

    if (cf.time_total > cf.bantime)
	life = cf.time_total * 2;
    else
	life = cf.bantime * 2;

    /* lock row */
    ngx_shmtx_lock(&ctx->hash_locks[key]);
    stats->np++;
    /* take head after lock */
    head = ctx->hash_heads[key];

    stats->hits++;
    /* lookup node */    
    while (head) {
	stats->run++;
	/* match */
	if (head->ip == addr)
		break;
		
	/* not matched, check if old */
	if (now - head->ts > life) {
	    if (prev)
	        prev->next = head->next;
		
	    node = head;
	    head = head->next;
			
	    /* special case - freeing head */
	    if (node == ctx->hash_heads[key]) 
	    	ctx->hash_heads[key] = head;

	    if (cf.check_url)
		ngx_slab_free(shpool, node->uri);
	    ngx_slab_free(shpool, node);
	    
	    stats->nodes--;
	} else {
	    prev = head;
	    head = head->next;
	}
    }
    
    if (head) {
	node=head;
	stats->old++;
	goto out;
    }

    node = rlimit_node_alloc(&cf, shpool, addr, now, &(r->request_line)); 
    
    if (node == NULL) {
	ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "rlimit_module-%s: rlimit_node_alloc: >>> OUT OF MEMORY! (total nodes: %d) <<<", VERSION, stats->nodes);
	ret=NGX_HTTP_INTERNAL_SERVER_ERROR;
	goto out_no_check;
    }

    stats->nodes++;

    node->next = ctx->hash_heads[key];
    ctx->hash_heads[key] = node;
    
    goto out_no_check;
    
out:
    /* if banned do not check url */
    if (node->bantill > now) {
    	ret=NGX_HTTP_INTERNAL_SERVER_ERROR;
	goto out_no_check;
    }
 
    /* check url */
    if (cf.check_url) {
	ret = rlimit_check_url(r, shpool, node);
	if (ret != NGX_OK) {
	    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "rlimit_module-%s: rlimit_check_url: >>> OUT OF MEMORY! (total nodes: %d) <<<", VERSION, stats->nodes);
	    goto out_no_check;
	}
    }

//ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "rlimit_module-%s: -------- %d + %d", VERSION, node->hitweight, node->hits);

    /* check hitrate */
    ret = rlimit_check_node(&cf, node, now, r);
    goto out_no_check;
    
out_no_check:
    stats->np--;
    ngx_shmtx_unlock(&ctx->hash_locks[key]);
    
    if (!((stats->hits) & REPORT_MASK) && (cf.log > 2))
	ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "rlimit_module-%s: statistic: hits: %d, nodes: %d, run: %d, cached: %d, crits: %d",
	    VERSION, stats->hits, stats->nodes, stats->run, stats->old, stats->np);

    if (ret != NGX_DECLINED && cf.error_code)
	return cf.error_code;
    else
	return ret;
}


static ngx_int_t ngx_http_rlimit_init_shared(ngx_shm_zone_t * shm_zone, void * data) {
    ngx_http_rlimit_ctx_t * octx=data;
    ngx_http_rlimit_ctx_t * ctx;
    ngx_slab_pool_t * shpool;
    ngx_int_t i;
    ngx_shmtx_sh_t * addrs;
    
    ctx = shm_zone->data;
    
    if (octx) {
	ngx_log_error(NGX_LOG_NOTICE, shm_zone->shm.log, 0, "rlimit_module-%s: octx not null, octx->hash_heads = %p", VERSION, octx->hash_heads);
	
	ctx->hash_heads = octx->hash_heads;
	ctx->hash_locks = octx->hash_locks;
	ctx->stats = octx->stats;

	if (ctx->stats->np)
	    ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0, "rlimit_module: >>> INITIALIZATION IN CRITICAL SECTION!!! <<<");
	
	ngx_log_error(NGX_LOG_NOTICE, shm_zone->shm.log, 0, "rlimit_module-%s: statistic: hits: %d, nodes: %d, run: %d, cached: %d, crits: %d",
	    VERSION, ctx->stats->hits, ctx->stats->nodes, ctx->stats->run, ctx->stats->old, ctx->stats->np);

	ctx->stats->hits = 0;
	ctx->stats->run = 0;
	ctx->stats->old = 0;
	
	return NGX_OK;
    }
    
    ngx_log_error(NGX_LOG_NOTICE, shm_zone->shm.log, 0, "rlimit_module-%s: octx is NULL, allocating heads. zone data: addr:%p, size:%ul", VERSION, shm_zone->shm.addr, shm_zone->shm.size);
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    
    ctx->hash_heads = ngx_slab_alloc(shpool, sizeof(rlimit_node_t *) * HASH_SIZE);
    if (ctx->hash_heads == NULL)
	return NGX_ERROR;
	
    ctx->hash_locks = ngx_slab_alloc(shpool, sizeof(ngx_shmtx_t) * HASH_SIZE);
    if (ctx->hash_locks == NULL)
	return NGX_ERROR;

#ifndef NGX_HAVE_ATOMIC_OPS
#error "You definetly need NGX_HAVE_ATOMIC_OPS defined for this to work! DO NOT USE THE BUILD EVEN IF SUCCEEDED!"
#endif
	
    addrs = ngx_slab_alloc(shpool, sizeof(ngx_shmtx_sh_t) * HASH_SIZE);
    if (addrs == NULL)
	return NGX_ERROR;
	
    for (i=0; i<HASH_SIZE; i++)
	if (ngx_shmtx_create(&ctx->hash_locks[i], &addrs[i], NULL) != NGX_OK) /* XXX x86 arch only! */
	    return NGX_ERROR; 

    ctx->stats = ngx_slab_alloc(shpool, sizeof(rlimit_stats_t));
    if (ctx->stats == NULL)
	return NGX_ERROR;

    return NGX_OK;
}


static char * ngx_http_rlimit_create_pool(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_rlimit_ctx_t * ctx;
    ssize_t n;
    ngx_shm_zone_t * shm_zone;
    ngx_str_t *value;
    ngx_conf_t save;
    rlimit_conf_t rconf;
    char * rv, name[256];
    
    value = cf->args->elts;

    /* This is Very Ugly (tm) */
    strcpy(name, (char *)(value[1].data));

    n = ngx_parse_size(&value[2]);
    if ((n == NGX_ERROR) || (n < MINPOOLSIZE))
	return "rlimit_module: invalid size of rlimit pool or value too small";

    /* allocate shared zone */    
    shm_zone = ngx_shared_memory_add(cf, &value[1], n, &ngx_http_rlimit_module);
    if (shm_zone == NULL)
	return "rlimit_module: unable to allocate shared memory";

    if (shm_zone->data)
	return "rlimit_module: shared zone with this identifier already exists";

    /* allocate context. all data is within context. */
    ctx = ngx_palloc(cf->pool, sizeof(ngx_http_rlimit_ctx_t));
    if (ctx == NULL)
	return NGX_CONF_ERROR;

    memset(&ctx->conf, 0, sizeof(rlimit_conf_t));

    shm_zone->init = ngx_http_rlimit_init_shared;
    shm_zone->data = ctx;

    /* parse block data */
    save = *cf;
    cf->ctx = ctx;
    cf->handler = ngx_http_rlimit_parse_block;
    cf->handler_conf = conf;
    
    rv = ngx_conf_parse(cf, NULL);
    
    *cf = save;
    
    if (rv != NGX_CONF_OK)
	return rv;
	
    rconf = ctx->conf;
    
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "rlimit_module-%s: pool \"%s\" created: size: %d, burst: %d in %ds, total: %d in %ds, ban: %ds, log: %d, internal requests: %s, check url: %s, error_code: %d", 
	VERSION, name, n, rconf.requests_burst, rconf.time_burst, rconf.requests_total, rconf.time_total, rconf.bantime, rconf.log, rconf.internal_off ? "OFF" : "ON", rconf.check_url ? "ON" : "OFF", rconf.error_code);

    return NGX_CONF_OK;
}


static char * ngx_http_rlimit_parse_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_rlimit_ctx_t * ctx;
    rlimit_conf_t *rcf;
    ngx_str_t * value;
    
    ctx = cf->ctx;
    rcf = &(ctx->conf);

    value = cf->args->elts;
    
    if (!ngx_strcmp(value[0].data, "total")) {
	if (cf->args->nelts != 3)
	    return "rlimit_module: usage: total REQUESTS TIME";
	
	rcf->time_total = ngx_parse_time(&value[2], 1);
	if (rcf->time_total == NGX_ERROR)
	    return "rlimit_module: total: invalid time value";
	    
	rcf->requests_total = ngx_atoi(value[1].data, value[1].len);
	if (rcf->requests_total == NGX_ERROR)
	    return "rlimit_module: total: invalid requests value";	
    }
    else if (!ngx_strcmp(value[0].data, "burst")) {
	if (cf->args->nelts != 3)
	    return "rlimit_module: usage: burst REQUESTS TIME";
	
	rcf->time_burst = ngx_parse_time(&value[2], 1);
	if (rcf->time_burst == NGX_ERROR)
	    return "rlimit_module: burst: invalid time value";
	    
	rcf->requests_burst = ngx_atoi(value[1].data, value[1].len);
	if (rcf->requests_burst == NGX_ERROR)
	    return "rlimit_module: burst: invalid requests value";	
    }
    else if (!ngx_strcmp(value[0].data, "ban")) {
    	if (cf->args->nelts != 2)
	    return "rlimit_module: usage: ban TIME";
	
	rcf->bantime = ngx_parse_time(&value[1], 1);
	if (rcf->bantime == NGX_ERROR)
	    return "rlimit_module: ban: invalid time value";
    }
    else if (!ngx_strcmp(value[0].data, "log")) {
    	if (cf->args->nelts != 2)
	    return "rlimit_module: usage: log LEVEL";

	rcf->log = ngx_atoi(value[1].data, value[1].len);
	if (rcf->log == NGX_ERROR)
	    return "rlimit_module: log: invalid log level value";	
    }
    else if (!ngx_strcmp(value[0].data, "error_code")) {
    	if (cf->args->nelts != 2)
	    return "rlimit_module: usage: error_code CODE";

	rcf->error_code = ngx_atoi(value[1].data, value[1].len);
	if (rcf->error_code == NGX_ERROR)
	    return "rlimit_module: error_code: invalid error code value, digit required";	
    }
    else if (!ngx_strcmp(value[0].data, "whitelist")) {
	unsigned int i;
	ngx_int_t rc;
	ngx_cidr_t cidr;
	
	for (i=0; i<cf->args->nelts-1; i++) {
	    if (i == MAX_WHITES)
		return "rlimit_module: whitelist: too many addresses. recompile with MAX_WHITES increased.";

	    rc = ngx_ptocidr(&(value[i+1]), &cidr);
	    
	    if (rc != NGX_OK)
		return "rlimit_module: whitelist: invalid address or mask";
		
	    if (cidr.family != AF_INET)
		return "rlimit_module: whitelist: only ipv4 supported.";
	
	    rcf->whites[i].mask=cidr.u.in.mask;
	    rcf->whites[i].addr=cidr.u.in.addr;
	    
	
	    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "whitelist: \"%V\" added as white", &value[i+1]);
	}
    }
    else if (!ngx_strcmp(value[0].data, "internal")) {
	if (cf->args->nelts != 2)
	    return "rlimit_module: usage: internal on/off";
	if (!ngx_strncmp((unsigned char *)"on", value[1].data, value[1].len))
	    rcf->internal_off = 0;
	else if (!ngx_strncmp((unsigned char *)"off", value[1].data, value[1].len))
	    rcf->internal_off = 1;
	else
	    return "rlimit_module: usage: internal on/off";
    }
    else if (!ngx_strcmp(value[0].data, "check_url")) {
	if (cf->args->nelts != 2)
	    return "rlimit_module: usage: check_url on/off";
	if (!ngx_strncmp((unsigned char *)"on", value[1].data, value[1].len))
	    rcf->check_url = 1;
	else if (!ngx_strncmp((unsigned char *)"off", value[1].data, value[1].len))
	    rcf->check_url = 0;
	else
	    return "rlimit_module: usage: check_url on/off";
    }
    else {
	return "rlimit_module: unknown directive in rlimit block";
    }
	
    return NGX_CONF_OK;
}


static char * ngx_http_rlimit_attach_pool(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t  *value;
    ngx_http_rlimit_loc_conf_t * rlcf = conf;

    value = cf->args->elts;

    if (rlcf->shm_zone)
    	return "rlimit_module: this location already attached to a shared pool";

    rlcf->shm_zone = ngx_shared_memory_add(cf, &value[1], 0, &ngx_http_rlimit_module);
    if (rlcf->shm_zone == NULL)
	return "rlimit_module: shared zone with id doesnt exist";
	
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "ngx_http_rlimit_attach_pool: \"%V\"", &value[1]);
	
    return NGX_CONF_OK;
}

static void *
ngx_http_rlimit_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_rlimit_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_rlimit_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}


static char *
ngx_http_rlimit_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_rlimit_loc_conf_t  *prev = parent;
    ngx_http_rlimit_loc_conf_t  *conf = child;
    
    /* pass zone down */
    if (!conf->shm_zone)
	conf->shm_zone=prev->shm_zone;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_rlimit_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_rlimit_handler;

    return NGX_OK;
}


