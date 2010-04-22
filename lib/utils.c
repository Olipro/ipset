/* Copyright 2007-20010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * This program is free software; you can redistribute it and/or modify   
 * it under the terms of the GNU General Public License version 2 as 
 * published by the Free Software Foundation.
 */
#include <assert.h>				/* assert */
#include <stdbool.h>				/* bool */
#include <stdlib.h>				/* malloc, free */
#include <string.h>				/* memset, str* */

#include <libipset/session.h>			/* ipset_err */
#include <libipset/utils.h>			/* prototypes */

/**
 * ipset_strchr - locate character(s) in string
 * @str: string to locate the character(s) in
 * @sep: string of characters to locate
 *
 * Return a pointer to the first occurence of any of the
 * characters to be located in the string. NULL is returned
 * if no character is found.
 */
char *
ipset_strchr(const char *str, const char *sep)
{
	char *match;
	
	assert(str);
	assert(sep);
	
	for (; *sep != '\0'; sep++)
		if ((match = strchr(str, (int)sep[0])) != NULL)
			return match;
	
	return NULL;
}

/**
 * ipset_name_match - match a string against an array of strings
 * @arg: string
 * @name: array of strings, last one is a NULL pointer
 *
 * Return true if arg matches any of the strings in the array.
 */
bool
ipset_name_match(const char *arg, const char * const name[])
{
	int i = 0;
	
	assert(arg);
	assert(name);
	
	while (name[i]) {
		if (STREQ(arg, name[i]))
			return true;
		i++;
	}
	
	return false;
}

/**
 * ipset_shift_argv - shift off an argument
 * @arc: argument count
 * @argv: array of argument strings
 * @from: from where shift off an argument
 *
 * Shift off the argument at "from" from the array of
 * arguments argv of size argc.
 */
void
ipset_shift_argv(int *argc, char *argv[], int from)
{
	int i;
	
	assert(*argc >= from + 1);

	for (i = from + 1; i <= *argc; i++) {
		argv[i-1] = argv[i];
	}
	(*argc)--;
	return;
}

/**
 * ipset_strncpy - copy the string from src to dst
 * @dst: the target string buffer
 * @src: the source string buffer
 * @len: the length of bytes to copy, including the terminating null byte.
 *
 * Copy the string from src to destination, but at most len bytes are
 * copied. The target is unconditionally terminated by the null byte.
 */
void
ipset_strncpy(char *dst, const char *src, size_t len)
{
	assert(dst);
	assert(src);

	strncpy(dst, src, len);
	dst[len - 1] = '\0';
}
