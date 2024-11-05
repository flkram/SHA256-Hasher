#include "sha256.h"

static void usage()
{
    fprintf( stderr, "usage: hash [input_file]\n" );
    exit( EXIT_FAILURE );
}

int main (int argc, char*argv[])
{
    FILE *file;
    if (argc==1){
        file = stdin;
    }
    else if (argc==2){
        file = fopen(argv[1], "r");
        if (file==NULL){
            fprintf(stderr, "missing-input-file.txt: No such file or directory\n");
            return EXIT_FAILURE;
        }
    }
    else{
        usage();
    }

    SHAState *state = makeState();
    byte *data = malloc(sizeof(byte)* BLOCK_SIZE);
    int num_read = 0;
    int c;
    while ((c=fgetc(file))!=EOF){
        data[num_read]=(byte)c;
        num_read++;
        if (num_read%64==0){
            data = realloc(data, (num_read+BLOCK_SIZE)*sizeof(byte));
        }
    }
    word hash[ HASH_WORDS ];

    update(state, data, num_read);
    digest(state, hash);

    for (int i = 0; i<HASH_WORDS; i++){
        printf("%08x", hash[i]);
    }
    printf("\n");
    
    fclose(file);
    free(data);
    free(state);
    return EXIT_SUCCESS;
}