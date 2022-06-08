#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/buffer_cache.h"
#include "threads/thread.h"
#include "lib/string.h"


#define PATH_MAX 256
//NAME_MAX 14


/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");
  bc_init();
  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();

  thread_current ()->current_dir = dir_open_root ();
  dentry_init(&dentry_cache);
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
  bc_term();
  dentry_destroy(&dentry_cache);
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  block_sector_t inode_sector = 0;

  char file_name [NAME_MAX+1];
  struct dir *dir = parse_path(name, file_name);
  //struct dir *dir = dir_open_root ();


  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, 0)
                  && dir_add (dir, file_name, inode_sector));
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  //char file_name[NAME_MAX+1]; 
  char* file_name = calloc(1, NAME_MAX +1 );
  struct inode *inode;
  char temp[NAME_MAX+1];
  struct dir *dir;
  struct dc_entry *dce;
  bool absolute_file = false;

  if (name[0]=='/')
    absolute_file = true;

  if (absolute_file){
    if ((dce = dentry_search(name))!=NULL){
      free(file_name);
      return file_open(inode_open(dce->inumber));
    }

    else{
      char * name_temp = malloc(strlen(name) + 1);
      strlcpy(name_temp, name, strlen(name) + 1);
      int i=0;
      int j = 0;
      while (name_temp[j] != '\0'){
        if (name_temp[j] == '/')
          i++;
        //name_temp++;
        j++;
      }
      free(name_temp);
      // char *name_temp = malloc(strlen(name)+1);
      // strlcpy(name_temp, name, strlen(name)+1);
      
      // int i=0;
      // while (*name_temp != '\0'){
      //   if (*name_temp == '/')
      //     i++;
      //   name_temp++;
      // }
      // free(name_temp);
      
      if (i>1){
        if ((dce = dentry_parent_search(name))!=NULL){
          dir = dir_open(inode_open(dce->inumber));

          char *name_temp2=malloc(strlen(name)+1);
          strlcpy(name_temp2, name, strlen(name)+1);
          file_name = strrchr(name_temp2, '/');
          free(name_temp2);
        }
        else{
          dir = parse_path(name, file_name);
        }
      }
      else
        dir = parse_path(name, file_name);
    }
  }

  else{
    dir = parse_path(name, file_name);
  }

  //struct dir *dir = dir_open_root ();
  if (dir == NULL){
    //dir_close(dir);
    free(file_name);
    return NULL;
  }
  
  if (!dir_lookup (dir, file_name, &inode)){
    free(file_name);
    dir_close(dir);
    return NULL;
  }

  if (absolute_file){
    dce = malloc(sizeof(struct dc_entry));
    dce->inumber = inode_get_inumber(inode);
    dce->path = (char *)malloc(strlen(name)+1);  
    strlcpy(dce->path, name, strlen(name)+1);
    //dce->path = (char *)malloc(strlen(name)+1); //do we have to strlcpy?
    if(!dentry_insertion(&dentry_cache, dce)){
      free(file_name);
      dir_close(dir);
      return NULL;
    }
  }

  //dir_lookup (dir, file_name, &inode);
  dir_close (dir);
  free(file_name);
  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  bool success = false;
  //char file_name[NAME_MAX+1]; 
  char* file_name = calloc(1, NAME_MAX +1 );
  struct inode *inode;
  struct dir *current_dir = NULL;
  char temp[NAME_MAX+1];
  struct dir *dir;
  struct dc_entry *dce;
  bool absolute_file = false;
  bool hit = false;

  if (name[0]=='/')
    absolute_file = true;

  if (absolute_file){
    if ((dce = dentry_search(name))!=NULL){
      hit = true;

      char * name_temp = malloc(strlen(name) + 1);
      strlcpy(name_temp, name, strlen(name) + 1);
      int i=0;
      int j = 0;
      while (name_temp[j] != '\0'){
        if (name_temp[j] == '/')
          i++;
        //name_temp++;
        j++;
      }
      free(name_temp);      
      // char *name_temp = malloc(strlen(name)+1);
      // strlcpy(name_temp, name, strlen(name)+1);
      
      // int i=0;
      // while (*name_temp != '\0'){
      //   if (*name_temp == '/')
      //     i++;
      //   name_temp++;
      // }
      // free(name_temp);
      
      if (i>1){
        if ((dce = dentry_parent_search(name))!=NULL){
          dir = dir_open(inode_open(dce->inumber));

          char *name_temp2=malloc(strlen(name)+1);
          strlcpy(name_temp2, name, strlen(name)+1);
          file_name = strrchr(name_temp2, '/');
          free(name_temp2);
        }
        else{
          dir = parse_path(name, file_name);
        }
      }
      else{
        dir = parse_path(name, file_name);
      }
    }
    else{
      dir = parse_path(name, file_name);
    }
  }

  else{
    dir = parse_path(name, file_name);
  }

  if (dir == NULL){
    free(file_name);
    return success;
  }

  if (!dir_lookup (dir, file_name, &inode)){
    free(file_name);
    dir_close(dir);
    return success;
  }


  if (inode_is_dir(inode) == 1){ // directory
    
    struct dir * t_dir = thread_current()->current_dir;
    struct inode * inode_ = dir_get_inode(t_dir);

    if(inode_ == inode){
      free(file_name);
      dir_close(dir);
      return success;
    }
    
    int cnt = inode_open_cnt(inode);
    if (cnt>1){
      free(file_name);
      dir_close(dir);
      return success;
    }
    
    current_dir = dir_open(inode);
    if (current_dir == NULL){
      free(file_name);
      dir_close(dir);
      return success;
    }
    
    if (dir_readdir(current_dir, temp) == 0){
      if (dir_remove (dir, file_name)){
        success = true;
      }
    }

    if (success && hit){
      if (!dentry_deletion(&dentry_cache, dce)){
        success = false;
      }
    }

    dir_close (current_dir);
  }

  else{ // file
    if(dir_remove (dir, file_name)){
      success = true;
    }
    
    // if (success && hit){
    //   if (!dentry_deletion(&dentry_cache, dce)){
    //     success = false;
    //   }
    //} 
  }
  free(file_name);
  dir_close (dir); 
  return success;
}


/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  
  struct dir *root_dir = dir_open_root();
  dir_add(root_dir, ".", ROOT_DIR_SECTOR);
  dir_add(root_dir, "..", ROOT_DIR_SECTOR);
  dir_close (root_dir);

  free_map_close ();
  printf ("done.\n");
}




struct dir *parse_path (char *path_name, char *file_name){

  struct dir *dir;

  if (path_name == NULL || file_name == NULL){
    //goto fail;
    return NULL;
  }

  if (strlen (path_name) == 0)
    return NULL;


  char path_copy [PATH_MAX];
  strlcpy (path_copy, path_name, PATH_MAX+1);

  if (path_copy[0] == '/')
    dir = dir_open_root ();
  else
    dir = dir_reopen (thread_current ()->current_dir);


  char *token, *nextToken, *savePtr;

  token = strtok_r (path_copy, "/", &savePtr);
  nextToken = strtok_r (NULL, "/", &savePtr);

  // if (token == NULL){
  //   strlcpy(file_name, ".", 2);
  //   return dir;
  // }

  if (token != NULL && nextToken == NULL && strlen(token) > NAME_MAX + 1){
    dir_close(dir);
    return NULL;
  }


  while (token != NULL && nextToken != NULL){
    struct inode *inode = NULL;

    if(strlen(token) >NAME_MAX + 1 || strlen(nextToken) > NAME_MAX +1){
      dir_close(dir);
      return NULL;
    }

    if (!dir_lookup(dir, token, &inode)){
      dir_close(dir);
      return NULL;
    }

    dir_close(dir);
    if (!inode_is_dir(inode)){
      return NULL;
    }

    dir = dir_open(inode);
    //token = nextToken;
    strlcpy(token, nextToken, PATH_MAX);
    nextToken = strtok_r (NULL, "/", &savePtr);
  }
  
  if (token==NULL)
    strlcpy(file_name, ".", 2);
  
  else
    strlcpy (file_name, token, PATH_MAX);
  return dir;
}



bool filesys_change_dir(const char *dir){

  if (strlen (dir) == 0)
    return false;
  char cp_dir[257];
  strlcpy(cp_dir, dir, 256);
  strlcat(cp_dir, "/0", 256);
  char file_name[NAME_MAX + 1];
  bool success = false;
  struct inode *inode;
  struct dir *directory;
  struct dir *change_directory;
  
  directory = parse_path (cp_dir, file_name);
  
  if (directory == NULL){
    return success;
  }
  
  if(!dir_lookup(directory,file_name, &inode))
    return success;

  change_directory = dir_open(inode);
  if (thread_current()->current_dir == NULL)
    thread_current()->current_dir = change_directory;
  else{
    dir_close(thread_current()->current_dir);
    thread_current()->current_dir = change_directory;
  }
  // dir_close (thread_current()->current_dir);
  
  // thread_current()->current_dir = directory;
  success = true;
  return success; 
}


bool filesys_create_dir(const char *name){

  block_sector_t inode_sector = 0;

  //char file_name [NAME_MAX+1];
  char* file_name = calloc(1, NAME_MAX +1 );
  struct dir *dir; 
  struct dc_entry *dce;
  bool absolute_file = false;

  if (name[0]=='/')
    absolute_file = true;

  if (absolute_file){
    if ((dce = dentry_search(name))!=NULL){
      free(file_name);
      return false;
    }

    else{
      char * name_temp = malloc(strlen(name) + 1);
      strlcpy(name_temp, name, strlen(name) + 1);
      int i=0;
      int j = 0;
      while (name_temp[j] != '\0'){
        if (name_temp[j] == '/')
          i++;
        //name_temp++;
        j++;
      }
      free(name_temp);
      // char *name_temp = malloc(strlen(name)+1);
      // strlcpy(name_temp, name, strlen(name)+1);
      
      // int i=0;
      // while (*name_temp != '\0'){
      //   if (*name_temp == '/')
      //     i++;
      //   name_temp++;
      // }
      // free(name_temp);
      
      if (i>1){
        if ((dce = dentry_parent_search(name))!=NULL){
          
          dir = dir_open(inode_open(dce->inumber));

          char *name_temp2=malloc(strlen(name)+1);
          strlcpy(name_temp2, name, strlen(name)+1);
          file_name = strrchr(name_temp2, '/');
          free(name_temp2);
        }
        else{
          dir = parse_path(name, file_name);
        }
      }
      else{
        dir = parse_path(name, file_name);
      }
    }
  }

  else{
    dir = parse_path(name, file_name);
  }

  //struct dir *dir = dir_open_root ();
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && dir_create (inode_sector, 16)
                  && dir_add (dir, file_name, inode_sector));
  if (!success && inode_sector != 0){ 
    free_map_release (inode_sector, 1);
  }

  if (success){
    struct inode *inode = inode_open (inode_sector);
    struct dir *directory = dir_open (inode);

    dir_add (directory, ".", inode_sector);

    struct inode * inode_ = dir_get_inode(dir);
    block_sector_t sector = inode_get_inumber(inode_);

    dir_add (directory, "..", sector);
    dir_close (directory);

    if (absolute_file){
      dce = malloc(sizeof(struct dc_entry));
      dce->inumber = inode_sector;
      dce->path = (char *)malloc(strlen(name)+1);  
      strlcpy(dce->path, name, strlen(name)+1);
      //dce->path = name;
      //dce->path = (char *)malloc(strlen(name)+1); //do we have to strlcpy?
      if(!dentry_insertion(&dentry_cache, dce))
        success = false;
    }
  }
  free(file_name);
  dir_close (dir);
  return success;
}

////// Similar with vm hash table implemented in page.c //////

void dentry_init (struct hash *dentry_cache){
	hash_init (dentry_cache, dentry_hash_function, dentry_less_function, NULL); 
}

void dentry_destroy (struct hash *dentry_cache){
	hash_destroy(dentry_cache, dentry_destructor);
}

void dentry_destructor (struct hash_elem *e, void *aux){
	struct dc_entry *dce = hash_entry (e, struct dc_entry, h_elem);
	free(dce);
}

static unsigned dentry_hash_function(const struct hash_elem *e, void *aux){
  
  struct dc_entry *dce = hash_entry(e, struct dc_entry, h_elem);
  unsigned hash_val = hash_string(dce->path);
  return hash_val;

}

static bool dentry_less_function (const struct hash_elem *e_a, const struct hash_elem *e_b, void *aux){

	struct dc_entry *dce_a;
	struct dc_entry *dce_b;
	
	dce_a = hash_entry (e_a, struct dc_entry, h_elem);
	dce_b = hash_entry (e_b, struct dc_entry, h_elem);

	char * path_a = dce_a->path;
	char * path_b = dce_b->path;

  if (strcmp(path_a, path_b)<0)
		return true;
	else
		return false;
}

bool dentry_insertion (struct hash *dentry_cache, struct dc_entry *dce){
	
	struct hash_elem *e;
	e = &dce->h_elem;	
	struct hash_elem *old = hash_insert(dentry_cache, e);
	return (old == NULL);
}
 
bool dentry_deletion (struct hash *dentry_cache, struct dc_entry *dce){
	struct hash_elem *e;
	e = &dce->h_elem;

	struct hash_elem *found = hash_delete(dentry_cache, e);
  if (found!=NULL){
    free(dce->path);
    free(dce);
  }
	return (found != NULL);
}

struct dc_entry *dentry_search (const char *path){

	struct dc_entry dce;

	dce.path = path;
	struct hash_elem *e = hash_find (&dentry_cache, &(dce.h_elem));   

	if (!e){
		return NULL;
  }

	return hash_entry(e, struct dc_entry, h_elem);
}

struct dc_entry *dentry_parent_search (const char *path){

  int i;
  
	struct dc_entry dce;


  char *path_temp = malloc(strlen(path)+1);
  

  strlcpy(path_temp, path, strlen(path)+1);
  
  for (i=strlen(path); i>=0; i--){
    if(path_temp[i]=="/")
      break;
  }
  char *path_parent = malloc(strlen(path)+1);
  strlcpy(path_parent, path_temp, i+1);

	dce.path = path_parent;
  struct dentry_cache* dce2 = dentry_search(dce.path);
	//struct hash_elem *e = hash_find (&dentry_cache, &(dce.h_elem));   

	// if (!e){
  //   free(path_temp);
  //   free(path_parent);
	// 	return NULL;
  // }
  // free(path_temp);
  // free(path_parent);
  return dce2;
	//return hash_entry(e, struct dc_entry, h_elem);
}