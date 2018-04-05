import std.conv:octal;
import core.stdc.config;
import core.stdc.stdarg: va_list;
import std.string;
import libetpan;

void check_error(int r, char * msg)
{
 if (r == MAILIMAP_NO_ERROR)
  return;
  if (r == MAILIMAP_NO_ERROR_AUTHENTICATED)
  return;
  if (r == MAILIMAP_NO_ERROR_NON_AUTHENTICATED)
  return;

 fprintf(stderr, "%s\n", msg);
 exit(1);
}

char * get_msg_att_msg_content(mailimap_msg_att * msg_att, size_t * p_msg_size)
{
 clistiter * cur;


 for(cur = msg_att.att_list.first ; cur != null ; cur = (cur ? (cur).next : null)) {
  mailimap_msg_att_item * item;

  item = cast(typeof(item))(cur ? cur.data : null);
  if (item.att_type != MAILIMAP_MSG_ATT_ITEM_STATIC) {
   continue;
  }

    if (item.att_data.att_static.att_type != MAILIMAP_MSG_ATT_BODY_SECTION) {
   continue;
    }

  * p_msg_size = item.att_data.att_static.att_data.att_body_section.sec_length;
  return item.att_data.att_static.att_data.att_body_section.sec_body_part;
 }

 return null;
}

char * get_msg_content(clist * fetch_result, size_t * p_msg_size)
{
 clistiter * cur;


 for(cur = fetch_result.first ; cur != null ; cur = (cur ? (cur).next : null)) {
  mailimap_msg_att * msg_att;
  size_t msg_size;
  char * msg_content;

  msg_att = cast(typeof(msg_att))(cur ? cur.data : null);
  msg_content = get_msg_att_msg_content(msg_att, &msg_size);
  if (msg_content == null) {
   continue;
  }

  * p_msg_size = msg_size;
  return msg_content;
 }

 return null;
}

static void fetch_msg(mailimap * imap, uint32_t uid)
{
    import std.file:exists;
  mailimap_set * set;
 mailimap_section * section;
 char filename[512];
 size_t msg_len;
 char * msg_content;
 FILE * f;
 mailimap_fetch_type * fetch_type;
 mailimap_fetch_att * fetch_att;
 int r;
 clist * fetch_result;
 stat stat_info;

 snprintf(filename.dup.ptr, filename.sizeof, "download/%u.eml".dup.ptr, cast(uint) uid);
 if(exists(filename))
  {
    //r = stat(filename.ptr, &stat_info);
 //if (r == 0) {

  printf("%u is already fetched\n", cast(uint) uid);
  return;
 }

 set = mailimap_set_new_single(uid);
 fetch_type = mailimap_fetch_type_new_fetch_att_list_empty();
 section = mailimap_section_new(null);
 fetch_att = mailimap_fetch_att_new_body_peek_section(section);
 mailimap_fetch_type_new_fetch_att_list_add(fetch_type, fetch_att);

 r = mailimap_uid_fetch(imap, set, fetch_type, &fetch_result);
 check_error(r, "could not fetch".dup.ptr);
 printf("fetch %u\n", cast(uint) uid);

 msg_content = get_msg_content(fetch_result, &msg_len);
 if (msg_content == null) {
  fprintf(stderr, "no content\n");
  mailimap_fetch_list_free(fetch_result);
  return;
 }

 f = fopen(filename.ptr, "w");
 if (f == null) {
  fprintf(stderr, "could not write\n");
  mailimap_fetch_list_free(fetch_result);
  return;
 }

 fwrite(msg_content, 1, msg_len, f);
 fclose(f);

 printf("%u has been fetched\n", cast(uint) uid);

 mailimap_fetch_list_free(fetch_result);
}

static uint32_t get_uid(mailimap_msg_att * msg_att)
{
 clistiter * cur;


 for(cur = ((msg_att.att_list).first) ; cur != null ; cur = (cur ? (cur).next : null)) {
  mailimap_msg_att_item * item;

  item = cast(typeof(item))(cur ? cur.data : null);
  if (item.att_type != MAILIMAP_MSG_ATT_ITEM_STATIC) {
   continue;
  }

  if (item.att_data.att_static.att_type != MAILIMAP_MSG_ATT_UID) {
   continue;
  }

  return item.att_data.att_static.att_data.att_uid;
 }

 return 0;
}

static void fetch_messages(mailimap * imap)
{
 mailimap_set * set;
 mailimap_fetch_type * fetch_type;
 mailimap_fetch_att * fetch_att;
 clist * fetch_result;
 clistiter * cur;
 int r;




 set = mailimap_set_new_interval(1, 0);
 fetch_type = mailimap_fetch_type_new_fetch_att_list_empty();
 fetch_att = mailimap_fetch_att_new_uid();
 mailimap_fetch_type_new_fetch_att_list_add(fetch_type, fetch_att);

 r = mailimap_fetch(imap, set, fetch_type, &fetch_result);
 check_error(r, "could not fetch".dup.ptr);


 for(cur = ((fetch_result).first) ; cur != null ; cur = (cur ? (cur).next : null)) {
  mailimap_msg_att * msg_att;
  uint32_t uid;

  msg_att = cast(typeof(msg_att))(cur ? (cur).data : null);
  uid = get_uid(msg_att);
  if (uid == 0)
   continue;

  fetch_msg(imap, uid);
 }

 mailimap_fetch_list_free(fetch_result);
}

int main(string[] args)
{
 mailimap * imap;
 int r;

 if (args.length < 3) {
  fprintf(stderr, "usage: imap-sample [gmail-email-address] [password]\n".dup.ptr);
  exit(1);
 }

 mkdir("download", octal!700);

 imap = mailimap_new(0, null);
 r = mailimap_ssl_connect(imap, "imap.gmail.com".dup.ptr, 993);
 fprintf(stderr, "connect: %i\n".dup.ptr, r);
 check_error(r, "could not connect to server".dup.ptr);

 r = mailimap_login(imap, args[1].toStringz, args[2].toStringz);
 check_error(r, "could not login".dup.ptr);

 r = mailimap_select(imap, "INBOX".dup.ptr);
 check_error(r, "could not select INBOX".dup.ptr);

 fetch_messages(imap);

 mailimap_logout(imap);
 mailimap_free(imap);

 return 0;
}
