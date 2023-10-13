#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/stat.h>

#define NUM_ELEMENTS 6
#define MAX_MICROSTATE 3

typedef struct {
    unsigned int elements[NUM_ELEMENTS];
} state_t;

typedef struct {
    state_t from;
    state_t to;
    _Bool forbidden;
} transition_t;

void free_state(state_t *state);

state_t *create_state_generic(const char *input, unsigned int max_microstate, unsigned n_microstates) {
    state_t *out = NULL;
    if (max_microstate > 9) {
        return out;
    }
    if (!input) {
        return out;
    }
    unsigned int elements[n_microstates];
    for (int i = 0; i < n_microstates; i++) {
        _Bool match = false;
        for (int j = 0; j <= max_microstate; j++) {
            unsigned char micro = j + '0';
            int rc = memcmp(&micro, (input + i), 1);
            if (rc == 0) {
                elements[i] = j;
                match = true;
            }
        }
        if (!match) {
            fprintf(stderr, "Possible invalid microstate \"%c\".\n", input[i]);
            return out;
        }
    }
    int n_nonzero = 0;
    for (int i = 0; i < n_microstates; i++) {
        if (elements[i]) {
            ++n_nonzero;
        }
        if (n_nonzero > 1) {
            fprintf(stderr, "%d non-zero elements in state.\n", n_nonzero);
            return out;
        }
    }
    out = (state_t *) malloc(sizeof(state_t));
    for (int i = 0; i < n_microstates; i++) {
        out->elements[i] = elements[i];
    }
    return out;
}

state_t *create_state(const char *input) {
    return create_state_generic(input, MAX_MICROSTATE, NUM_ELEMENTS);
}

char *print_state_generic(const state_t *state, unsigned int n_microstates) {
    char *output = NULL;
    char state_str[n_microstates + 1];
    state_str[n_microstates] = '\0';
    for (int i = 0; i < n_microstates; i++) {
        unsigned int element = state->elements[i];
        if (element > 9) {
            return output;
        } else {
            state_str[i] = (char) (element + '0');
        }
    }
    output = (char *) malloc(sizeof(char) * (n_microstates + 1));
    output[n_microstates] = '\0';
    strcpy(output, state_str);
    return output;
}

char *print_state(const state_t *state, unsigned int *n) {
    char *output = NULL;
    output = print_state_generic(state, NUM_ELEMENTS);
    if (!output) {
        *n = 0;
    } else {
        *n = NUM_ELEMENTS;
    }
    return output;
}

_Bool states_equal_generic(const state_t *left, const state_t *right, unsigned int n_microstates) {
    _Bool is_equal = true;
    for (int i = 0; i < n_microstates; i++) {
        if (left->elements[i] != right->elements[i]) {
            is_equal = false;
            break;
        }
    }
    return is_equal;
}

_Bool states_equal(const state_t *left, const state_t *right) {
    return states_equal_generic(left, right, NUM_ELEMENTS);
}

typedef struct {
    size_t size;
    char *content;
} line_t;

typedef struct {
    size_t size;
    line_t *lines;
} lines_t;

void free_line(line_t *line) {
    if (!line) return;
    free(line->content);
    free(line);
}

void free_lines(lines_t *lines) {
    if (!lines) return;
    line_t *line = NULL;
    for (int i = 0; i < lines->size; i++) {
        line = lines->lines + i;
        free(line->content);
    }
    free(lines->lines);
    free(lines);
}

line_t *without_comments(const line_t *line) {
    line_t *output = NULL;
    if (!line) return output;
    if (!line->size) return output;
    if (line->size > 2147483648) return output;  // limiting to 2GB
    char local[line->size + 1];
    local[line->size] = '\0';
    memcpy(&local[0], line->content, line->size);
    size_t n = strcspn(local, "#");
    if (!n) return output;
    output = (line_t *) malloc(sizeof(line_t));
    output->content = (char *) malloc(sizeof(char) * (n + 1));
    memcpy(output->content, local, n);
    output->content[n] = '\0';
    output->size = n + 1;
    return output;
}

_Bool is_line_min_size(const line_t *line, size_t min_size) {
    if (!line) return NULL;
    if (!min_size) return NULL;
    char local_line[line->size + 1];
    local_line[line->size] = '\0';
    memcpy(local_line, line->content, line->size);
    if (strlen(local_line) < min_size) {
        return false;
    } else {
        return true;
    }
}

lines_t *get_lines(const char *buffer, size_t buffer_size) {
    lines_t *output = NULL;
    lines_t l = {
            .size = 0,
            .lines = NULL,
    };
    if (!buffer) return output;
    if (!buffer_size) return output;
    if (buffer_size > 2147483648) return output;  // limiting to 2GB
    char local_buffer[buffer_size + 1];
    memcpy(local_buffer, buffer, buffer_size);
    local_buffer[buffer_size] = '\0';
    char ref_line[] = "000000 000000";
    line_t *temp_line = NULL, local_line;
    size_t ref_len = strlen(ref_line);
    for (char *s = local_buffer; (s = strtok(s, "\n")); s = NULL) {
        local_line.content = s;
        local_line.size = strlen(s) + 1;
        temp_line = without_comments(&local_line);
        if (!temp_line) {
            continue;
        }
        _Bool is_size_ok = is_line_min_size(temp_line, ref_len);
        if (!is_size_ok) {
            free_line(temp_line);
            continue;
        }
        l.lines = (line_t *) realloc(l.lines, ++l.size * sizeof(line_t));
        int j = (int) l.size - 1;
        l.lines[j].content = (char *) malloc(sizeof(char) * (temp_line->size));
        strcpy(l.lines[j].content, temp_line->content);
        l.lines[j].size = temp_line->size;
        free_line(temp_line);
        temp_line = NULL;
    }
    output = (lines_t *) malloc(sizeof(lines_t));
    output->lines = l.lines;
    output->size = l.size;
    return output;
}


typedef struct {
    size_t size;
    char *content;
} token_t;

typedef struct {
    size_t size;
    token_t *arr;
} tokens_t;

void free_token_arr(token_t *arr, size_t arr_size) {
    if (!arr) return;
    for (int i = 0; i < arr_size; i++) {
        if (arr[i].content) {
            free(arr[i].content);
        }
    }
    free(arr);
}

void free_tokens(tokens_t *tokens) {
    if (!tokens) return;
    if (!tokens->arr) {
        free(tokens);
        return;
    }
    for (int i = 0; i < tokens->size; i++) {
        free(tokens->arr[i].content);
    }
    free(tokens->arr);
    free(tokens);
}

tokens_t *line_tokens(line_t *line) {
    tokens_t *output = NULL;
    if (!line) return output;
    if (!line->size) return output;
    if (line->size > 2147483648) return output;  // limiting to 2GB
    char line_chars[line->size + 1];
    line_chars[line->size] = '\0';
    char ref_token[] = "000000", pair[2][strlen(ref_token) + 1];
    memcpy(&line_chars[0], line->content, line->size);
    int i = 0;
    for (char *s = &line_chars[0]; (s = strtok(s, " ")); s = NULL) {
        if (i > 1) return output;
        if (strlen(s) != strlen(ref_token)) return output;
        strcpy(&pair[i++][0], s);
    }
    token_t *token_arr = (token_t *) malloc(sizeof(token_t) * 2);
    for (int j = 0; j < 2; j++) {
        token_arr[j].content = (char *) malloc(sizeof(char) * (strlen(ref_token) + 1));
        strcpy(token_arr[j].content, &pair[j][0]);
        token_arr[j].size = strlen(ref_token) + 1;
    }
    output = (tokens_t *) malloc(sizeof(tokens_t));
    output->size = 2;
    output->arr = token_arr;
    return output;
}

char **state_tokens(const char *input_buffer, size_t buffer_size, unsigned int *n_tokens) {
    char **out = NULL;
    lines_t *lines = get_lines(input_buffer, buffer_size);
    if (!lines) {
        return out;
    }
    tokens_t *l_tokens = NULL;
    tokens_t tokens = {
            .size = 0,
            .arr = NULL,
    };
    for (int i = 0; i < lines->size; i++) {
        l_tokens = line_tokens(lines->lines + i);
        if (!l_tokens) {
            if (tokens.arr) {
                free_token_arr(tokens.arr, tokens.size);
            }
            return out;
        }
        for (int j = 0; j < l_tokens->size; j++) {
            tokens.arr = realloc(tokens.arr, sizeof(token_t) * ++tokens.size);
            tokens.arr[tokens.size - 1].content = (char *) malloc(sizeof(char) * l_tokens->arr[j].size);
            strcpy(tokens.arr[tokens.size - 1].content, l_tokens->arr[j].content);
        }
        free_tokens(l_tokens);
        l_tokens = NULL;
    }
    free_lines(lines);
    out = (char **) malloc(sizeof(char *) * tokens.size);
    for (int i = 0; i < tokens.size; i++) {
        out[i] = tokens.arr[i].content;
    }
    *(n_tokens) = tokens.size;
    return out;
}

state_t *parse_states(const char *input, size_t input_size, unsigned int *n_states) {
    state_t *output = NULL;
    unsigned int n_tokens = 0;
    char **tokens = state_tokens(input, input_size, &n_tokens);
    if (!tokens) return output;
    if (!n_tokens) return output;
    state_t states_arr[n_tokens], *temp_state;
    for (int i = 0; i < n_tokens; i++) {
        temp_state = create_state(tokens[i]);
        if (!temp_state) return output;
        states_arr[i] = *temp_state;
        free_state(temp_state);
    }
    output = malloc(sizeof(state_t) * n_tokens);
    for (int i = 0; i < n_tokens; i++) {
        output[i] = states_arr[i];
    }
    *n_states = n_tokens;
    return output;
}

void free_state(state_t *state) {
    if (!state) return;
    free(state);
}

transition_t *create_transition(const state_t *from, const state_t *to) {
    transition_t *transition = (transition_t *) malloc(sizeof(transition_t));
    transition->from = *from;
    transition->to = *to;
    transition->forbidden = false;
    return transition;
}

void free_transition(transition_t *transition) {
    if (!transition) return;
    free(transition);
}

transition_t *create_transitions(const state_t *states, unsigned int n_states, unsigned int *n_transitions) {
    transition_t *transitions = NULL;
    unsigned int mod_s = n_states % 2;
    if (mod_s != 0) {
        return transitions;
    }
    unsigned int nt = 0, half_n = n_states / 2;
    unsigned int j = 0;
    transition_t transition_arr[half_n];
    transition_t *transition_temp = NULL;
    for (int i = 0; i < (n_states / 2); i++) {
        j = i * 2;
        transition_temp = create_transition(states + j, states + j + 1);
        transition_arr[i] = *transition_temp;
        free_transition(transition_temp);
        transition_temp = NULL;
        ++nt;
    }
    *n_transitions = nt;
    transitions = (transition_t *) malloc(sizeof(transition_t) * (*n_transitions));
    for (int i = 0; i < *n_transitions; i++) {
        transitions[i] = transition_arr[i];
    }
    return transitions;
}

_Bool transitions_equal_generic(const transition_t *left, const transition_t *right, unsigned int n_microstates) {
    _Bool to_equal = states_equal_generic(&(left->to), &(right->to), n_microstates);
    _Bool from_equal = states_equal_generic(&(left->from), &(right->from), n_microstates);
    return (to_equal && from_equal);
}

_Bool transitions_equal(const transition_t *left, const transition_t *right) {
    return transitions_equal_generic(left, right, NUM_ELEMENTS);
}

void free_transitions(transition_t *transitions, const unsigned int n_transitions) {
    if (transitions) {
        free(transitions);
    }
}

char *print_transition_generic(transition_t *transition, unsigned int n_microstates) {
    char *output = NULL;
    char *to_str = print_state_generic(&transition->to, n_microstates);
    char *from_str = print_state_generic(&transition->from, n_microstates);
    if (!(to_str && from_str)) {
        return output;
    }
    size_t n = n_microstates * 2 + 2;
    output = (char *) malloc(sizeof(char) * n);
    memset(output, '\0', n);
    strncat(output, from_str, n_microstates);
    strcat(output, " ");
    strncat(output, to_str, n_microstates);
    free(to_str);
    free(from_str);
    return output;
}

char *print_transition(transition_t *transition) {
    return print_transition_generic(transition, NUM_ELEMENTS);
}

char *init_state_string(unsigned int n_elements, size_t *output_size) {
    char *output = (char *) malloc(n_elements + 1);
    memset(output, '0', n_elements);
    output[n_elements] = '\0';
    *output_size = n_elements + 1;
    return output;
}

transition_t *enumerate_transitions(unsigned int n_microstates, unsigned int max_microstate,
                                    unsigned int *out_size) {
    transition_t *output = NULL;
    size_t str_size = (size_t) n_microstates + 1;
    unsigned char temp_state_str[str_size];
    memset(&temp_state_str, '0', str_size - 1);
    temp_state_str[str_size - 1] = '\0';
    unsigned int n_states = (n_microstates * max_microstate) + 1;
    state_t states[n_states];
    state_t *temp_state = NULL;
    for (int i = 0; i < n_microstates; i++) {
        for (int j = 0; j < max_microstate; j++) {
            temp_state_str[i] = j + 1 + '0';
            temp_state = create_state_generic((char *) &temp_state_str, max_microstate, n_microstates);
            if (!temp_state) {
                fprintf(stderr, "Unable to create state from \"%s\".\n", (char *) &temp_state_str);
            }
            states[(i * max_microstate) + j] = *temp_state;
            free_state(temp_state);
            temp_state = NULL;
            memset(&temp_state_str, '0', str_size - 1);
        }
    }
    temp_state = create_state_generic((char *) &temp_state_str, max_microstate, n_microstates);
    states[n_states - 1] = *temp_state;
    free_state(temp_state);
    temp_state = NULL;
    unsigned int n_transitions = n_states * n_states;
    transition_t transitions[n_transitions];
    transition_t *temp_transition = NULL;
    for (int i = 0; i < n_states; i++) {
        for (int j = 0; j < n_states; j++) {
            unsigned int w = (i * n_states) + j;
            temp_transition = create_transition(&states[i], &states[j]);
            transitions[w] = *temp_transition;
            free_transition(temp_transition);
            temp_transition = NULL;
        }
    }
    output = (transition_t *) malloc(sizeof(transition_t) * n_transitions);
    for (int i = 0; i < n_transitions; i++) {
        *(output + i) = transitions[i];
    }
    *(out_size) = n_transitions;
    return output;
}

transition_t *filter_transitions(const transition_t *ref_set, const unsigned int n_ref, const transition_t *filter_set,
                                 const unsigned int n_filter, unsigned int *n_out) {
    transition_t *output = NULL;
    if (!(ref_set && filter_set)) {
        return output;
    }
    unsigned int n_left = n_ref;
    _Bool *mask = (_Bool *) malloc(sizeof(_Bool) * n_ref);
    for (int i = 0; i < n_ref; i++) {
        mask[i] = true;
    }
    for (int i = 0; i < n_filter; i++) {
        for (int j = 0; j < n_ref; j++) {
            if (mask[j]) {
                if (transitions_equal(&filter_set[i], &ref_set[j])) {
                    --n_left;
                    mask[j] = false;
                }
            }
        }
    }
    if (!n_left) {
        free(mask);
        return output;
    }
    output = (transition_t *) malloc(sizeof(transition_t) * n_left);
    unsigned int k = 0;
    for (int i = 0; i < n_ref; i++) {
        if (mask[i]) {
            output[k++] = ref_set[i];
        }
    }
    *n_out = k;
    free(mask);
    return output;
}

void print_forbidden(const char *file_name) {
    struct stat sb;
    if (stat(file_name, &sb) != 0) {
        fprintf(stderr, "'stat' failed for '%s': %s.\n",
                file_name, strerror(errno));
        exit(EXIT_FAILURE);
    }
    unsigned int file_size = sb.st_size;
    char *content = (char *) malloc(sizeof(char) * (file_size + 1));
    memset(content, '\0', file_size + 1);
    FILE *f = fopen(file_name, "r");
    if (!f) {
        fprintf(stderr, "Could not open '%s': %s.\n", file_name,
                strerror(errno));
        exit(EXIT_FAILURE);
    }
    size_t bytes_read = fread(content, sizeof(char), file_size, f);
    if (bytes_read != file_size) {
        fprintf(stderr, "Short read of '%s': expected %d bytes "
                        "but got %lu: %s.\n", file_name, file_size, bytes_read,
                strerror(errno));
        exit(EXIT_FAILURE);
    }
    int status = fclose(f);
    if (status != 0) {
        fprintf(stderr, "Error closing '%s': %s.\n", file_name,
                strerror(errno));
        exit(EXIT_FAILURE);
    }
    unsigned int n_states = 0;
    state_t *states = parse_states(content, file_size + 1, &n_states);
    if (!states) {
        fprintf(stderr, "Error: Failed to create states.\n");
        exit(EXIT_FAILURE);
    }
    unsigned int n_allowed = 0;
    transition_t *allowed_transitions = create_transitions(states, n_states, &n_allowed);
    if (!allowed_transitions) {
        fprintf(stderr, "Error: Failed to create allowed transitions.\n");
        exit(EXIT_FAILURE);
    }
    unsigned int n_all = 0;
    transition_t *all_transitions = enumerate_transitions(NUM_ELEMENTS, MAX_MICROSTATE, &n_all);
    if (!all_transitions) {
        fprintf(stderr, "Error: Failed to enumerate transitions.\n");
        exit(EXIT_FAILURE);
    }
    unsigned int n_forbidden = 0;
    transition_t *forbidden_transitions = filter_transitions(all_transitions, n_all, allowed_transitions, n_allowed,
                                                             &n_forbidden);
    if (!forbidden_transitions) {
        fprintf(stderr, "Error: Failed to filter out allowed transitions.\n");
        exit(EXIT_FAILURE);
    }
    char *buff = NULL;
    for (int i = 0; i < n_forbidden; i++) {
        buff = print_transition(forbidden_transitions + i);
        printf("%s\n", buff);
        free(buff);
        buff = NULL;
    }
    free(content);
    free_state(states);
    free_transitions(allowed_transitions, n_allowed);
    free_transitions(all_transitions, n_all);
    free_transitions(forbidden_transitions, n_forbidden);
}
