#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "../../src/unity/unity.h"

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

state_t *create_state_generic(const char *input, unsigned int max_microstate, unsigned n_microstates);

state_t *create_state(const char *input);

char *print_state_generic(const state_t *state, unsigned int n_microstates);

char *print_state(const state_t *state, unsigned int *n);

_Bool states_equal_generic(const state_t *left, const state_t *right, unsigned int n_microstates);

_Bool states_equal(const state_t *left, const state_t *right);

state_t *parse_states(const char *input, size_t input_size, unsigned int *n_states);

char **state_tokens(const char *input_buffer, size_t buffer_size, unsigned int *n_tokens);

transition_t *create_transition(const state_t *from, const state_t *to);

void free_transition(transition_t *transition);

transition_t *create_transitions(const state_t *states, unsigned int n_states, unsigned int *n_transitions);

_Bool transitions_equal_generic(transition_t *left, transition_t *right, unsigned int n_microstates);

_Bool transitions_equal(transition_t *left, transition_t *right);

void free_transitions(transition_t *transitions, const unsigned int n_transitions);

char *print_transition_generic(transition_t *transition, unsigned int n_microstates);

char *print_transition(transition_t *transition);

char *init_state_string(unsigned int n_elements, size_t *output_size);

transition_t *enumerate_transitions(unsigned int n_microstates, unsigned int max_microstate,
                                    unsigned int *out_size);

transition_t *filter_transitions(const transition_t *ref_set, const unsigned int n_ref, const transition_t *filter_set,
                                 const unsigned int n_filter, unsigned int *n_out);

void test_init_state_string(void) {
    char *expected[] = {
            "00",
            "000000",
            "0",
            "0000000000",
            "000",
            ""
    };
    unsigned int n_cases = (unsigned int) (sizeof(expected) / sizeof(expected[0]));
    unsigned int test_sizes[n_cases];
    for (int i = 0; i < n_cases; i++) {
        test_sizes[i] = strlen(expected[i]);
    }
    char *temp_string = NULL;
    size_t temp_size = 0;
    for (int i = 0; i < n_cases; i++) {
        temp_string = init_state_string(test_sizes[i], &temp_size);
        TEST_ASSERT_TRUE(temp_string);
        TEST_ASSERT_EQUAL_UINT(test_sizes[i] + 1, (unsigned int) temp_size);
        TEST_ASSERT_EQUAL_STRING(expected[i], temp_string);
        free(temp_string);
        temp_string = NULL;
        temp_size = 0;
    }
}

void test_enumerate_transitions(void) {
    char *state_chars[] = {
            "100",
            "200",
            "010",
            "020",
            "001",
            "002",
            "000"
    };
    unsigned int states_size = (unsigned int) (sizeof(state_chars) / sizeof(state_chars[0]));
    unsigned int transitions_size = states_size * states_size;
    state_t states[states_size];
    state_t *temp_state = NULL;
    for (int i = 0; i < states_size; i++) {
        temp_state = create_state_generic(state_chars[i], 2, 3);
        states[i] = *temp_state;
        free_state(temp_state);
        temp_state = NULL;
    }
    transition_t *transitions_ptr[transitions_size];
    for (int i = 0; i < states_size; i++) {
        for (int j = 0; j < states_size; j++) {
            unsigned int w = (i * states_size) + j;
            transitions_ptr[w] = create_transition(&states[i], &states[j]);
        }
    }
    transition_t transitions[transitions_size];
    for (int i = 0; i < transitions_size; i++) {
        transitions[i] = *transitions_ptr[i];
        free_transition(transitions_ptr[i]);
        transitions_ptr[i] = NULL;
    }
    unsigned int n_out = 0;
    transition_t *output = enumerate_transitions(3, 2, &n_out);
    TEST_ASSERT_EQUAL_UINT(transitions_size, n_out);
    unsigned int n_matches = 0;
    uint8_t mask[transitions_size];
    for (int i = 0; i < transitions_size; i++) {
        mask[i] = 1;
    }
    for (int i = 0; i < transitions_size; i++) {
        for (int j = 0; j < transitions_size; j++) {
            if (mask[j]) {
                if (transitions_equal_generic(&transitions[i], &output[j], 3)) {
                    ++n_matches;
                    mask[j] = 0;
                    break;
                }
            }
        }
    }
    free_transitions(output, n_out);
    TEST_ASSERT_EQUAL_UINT(transitions_size, n_matches);
}

void test_filter_transitions(void) {
    char *ref_state_chars[] = {
            "001000",
            "200000",
            "300000",
            "010000"
    };
    unsigned int ref_states_size = (unsigned int) (sizeof(ref_state_chars) / sizeof(ref_state_chars[0]));
    char *filter_chars[] = {
            "300000",
            "010000"
    };
    unsigned int filter_states_size = (unsigned int) (sizeof(filter_chars) / sizeof(filter_chars[0]));
    unsigned int n_left = 1;
    state_t ref_states[ref_states_size];
    state_t *temp_state = NULL;
    for (int i = 0; i < ref_states_size; i++) {
        temp_state = create_state(ref_state_chars[i]);
        ref_states[i] = *temp_state;
        free_state(temp_state);
        temp_state = NULL;
    }
    state_t filter_states[filter_states_size];
    for (int i = 0; i < filter_states_size; i++) {
        temp_state = create_state(filter_chars[i]);
        filter_states[i] = *temp_state;
        free_state(temp_state);
        temp_state = NULL;
    }
    unsigned int ref_tsize = 0;
    unsigned int filter_tsize = 0;
    transition_t *ref_transitions = create_transitions(&ref_states[0], ref_states_size, &ref_tsize);
    transition_t *toskip_transitions = create_transitions(&filter_states[0], filter_states_size, &filter_tsize);
    unsigned int n_out = 0;
    transition_t *out_transitions = filter_transitions(ref_transitions, ref_tsize, toskip_transitions, filter_tsize,
                                                       &n_out);
    TEST_ASSERT_TRUE(out_transitions);
    unsigned int matches = 0;
    for (int i = 0; i < n_out; i++) {
        for (int j = 0; j < filter_tsize; j++) {
            if (transitions_equal(&out_transitions[i], &toskip_transitions[j])) {
                ++matches;
            }
        }
    }
    free_transitions(ref_transitions, ref_tsize);
    free_transitions(toskip_transitions, filter_tsize);
    free_transitions(out_transitions, n_out);
    TEST_ASSERT_EQUAL_UINT(n_left, n_out);
    TEST_ASSERT_EQUAL_UINT(0, matches);
}

void test_transitions_equal(void) {
    char *state_chars[] = {
            "010000",
            "020000",
            "010000",
            "020000",
            "100000",
            "020000",
            "100000",
            "200000",
            "000003",
            "003000",
            "100000",
            "030000"
    };
    unsigned int n_states = (unsigned int) (sizeof(state_chars) / sizeof(state_chars[0]));
    _Bool matches[] = {
            true,
            false,
            false

    };
    unsigned int n_inputs = (unsigned int) (sizeof(matches) / sizeof(matches[0]));
    state_t *temp_state;
    state_t states[n_states];
    for (int i = 0; i < n_states; i++) {
        temp_state = create_state(state_chars[i]);
        states[i] = *(temp_state);
        free_state(temp_state);
        temp_state = NULL;
    }
    unsigned int n_transitions = 0;
    transition_t *transitions = create_transitions(states, n_states, &n_transitions);
    TEST_ASSERT_EQUAL_UINT((n_states / 2), n_transitions);
    TEST_ASSERT_EQUAL_UINT(n_inputs, (n_transitions / 2));
    for (int i = 0; i < (n_transitions / 2); i++) {
        TEST_ASSERT_TRUE(transitions_equal(&transitions[i * 2], &transitions[(i * 2) + 1]) == matches[i]);
    }
}

void test_print_transition(void) {
    char *input_chars[] = {
            "010000 020000",
            "100000 300000",
            "000000 000020"
    };
    unsigned int in_transitions = (unsigned int) (sizeof(input_chars) / sizeof(input_chars[0]));
    state_t *ptr_states[] = {
            create_state("010000"),
            create_state("020000"),
            create_state("100000"),
            create_state("300000"),
            create_state("000000"),
            create_state("000020")
    };
    unsigned int n_states = (unsigned int) (sizeof(ptr_states) / sizeof(ptr_states[0]));
    state_t states[n_states];
    for (int i = 0; i < n_states; i++) {
        states[i] = *(ptr_states[i]);
        free_state(ptr_states[i]);
        ptr_states[i] = NULL;
    }
    unsigned int out_transitions = 0;
    transition_t *transitions = create_transitions(states, n_states, &out_transitions);
    char *out_transition = NULL;
    for (int i = 0; i < out_transitions; i++) {
        out_transition = print_transition((transitions + i));
        TEST_ASSERT_EQUAL_CHAR_ARRAY(input_chars[i], out_transition, strlen(input_chars[i]));
        free(out_transition);
        out_transition = NULL;
    }
}

void test_print_state(void) {
    char *input_chars[] = {
            "010000",
            "200000",
            "000300"
    };
    unsigned int n_states = (unsigned int) (sizeof(input_chars) / sizeof(input_chars[0]));
    unsigned int n_chars = 0;
    char *output_chars = NULL;
    state_t *input_state = NULL;
    for (int i = 0; i < n_states; i++) {
        input_state = create_state(input_chars[i]);
        n_chars = 0;
        output_chars = print_state(input_state, &n_chars);
        TEST_ASSERT_TRUE(output_chars);
        free_state(input_state);
        TEST_ASSERT_EQUAL_UINT((unsigned int) strlen(input_chars[0]), n_chars);
        TEST_ASSERT_FALSE(memcmp(input_chars[i], output_chars, n_chars));
        if (output_chars) {
            free(output_chars);
            output_chars = NULL;
        }
        input_state = NULL;
    }

}

void test_create_transitions(void) {
    char *char_states[] = {
            "000000",
            "100000",
            "300000",
            "200000",
            "030000",
            "000001",
            "020000"
    };
    unsigned int n_states = (unsigned int) (sizeof(char_states) / sizeof(char_states[0]));
    state_t states[n_states];
    state_t *temp_state = NULL;
    for (int i = 0; i < n_states; i++) {
        temp_state = create_state(char_states[i]);
        states[i] = *temp_state;
        free_state(temp_state);
        temp_state = NULL;
    }
    unsigned int n_transitions = 0;
    transition_t *transitions = create_transitions(&states[0], n_states, &n_transitions);
    TEST_ASSERT_FALSE(transitions);
    TEST_ASSERT_FALSE(n_transitions);
    if (transitions) {
        free_transitions(transitions, n_transitions);
    }
    n_transitions = 0;
    transitions = NULL;
    transitions = create_transitions(&states[0], n_states - 1, &n_transitions);
    TEST_ASSERT_EQUAL_UINT(3, n_transitions);
    TEST_ASSERT_TRUE(transitions);
    free_transitions(transitions, n_transitions);
}

void test_parse_states() {
    char *input_buffer = "# 000000\n"
                         "\n"
                         "# 100000\n"
                         "000000 100000\n"
                         "300000 100000\n"
                         "200000 100000\n"
                         "030000 100000\n"
                         "\n"
                         "# 200000\n"
                         "100000 200000\n";
    char *char_states[] = {
            "000000",
            "100000",
            "300000",
            "100000",
            "200000",
            "100000",
            "030000",
            "100000",
            "100000",
            "200000",
    };
    unsigned int states_size = (unsigned int) (sizeof(char_states) / sizeof(char *));
    state_t states[states_size];
    state_t *temp_state;
    for (int i = 0; i < states_size; i++) {
        temp_state = create_state(char_states[i]);
        states[i] = *temp_state;
        free_state(temp_state);
    }
    unsigned int n_states = 0;
    state_t *output = parse_states(input_buffer, strlen(input_buffer), &n_states);
    TEST_ASSERT_TRUE(output);
    TEST_ASSERT_EQUAL_UINT(states_size, n_states);
    unsigned int n_matches = 0;
    _Bool *mask = (_Bool *) malloc(sizeof(_Bool) * n_states);
    for (int i = 0; i < n_states; i++) {
        mask[i] = true;
    }
    for (int i = 0; i < (int) states_size; i++) {
        for (int j = 0; j < n_states; j++) {
            if (mask[j]) {
                if (states_equal(&states[i], &output[j])) {
                    ++n_matches;
                    mask[j] = false;
                }
            }
        }
    }
    free(mask);
    TEST_ASSERT_EQUAL_UINT(states_size, n_matches);
}

void test_create_state() {
    state_t *a[] = {
            create_state("400000"),
            create_state(""),
            create_state("abcdef"),
            create_state("060000"),
            create_state("111119"),
            create_state(NULL),
            create_state("235000"),
            create_state("100822"),
            create_state("233340"),
            create_state("qrs"),
            create_state("100100"),
            create_state("200011"),
    };
    int num_states = (int) (sizeof(a) / sizeof(a[0]));
    state_t *b[num_states];
    for (int i = 0; i < num_states; i++) {
        b[i] = a[i];
        if (a[i]) {
            free_state(a[i]);
        }
    }
    for (int i = 0; i < num_states; i++) {
        TEST_ASSERT_FALSE(b[i]);
    }
}

void test_states_equal() {
    state_t *a = create_state("100000");
    state_t *b = create_state("100000");
    state_t *c = create_state("200000");
    _Bool ab = states_equal(a, b);
    _Bool ac = states_equal(a, c);
    free_state(a);
    free_state(b);
    free_state(c);
    TEST_ASSERT_TRUE(ab);
    TEST_ASSERT_FALSE(ac);
}

void test_state_tokens() {
    char *input_buffer = "# 000000\n"
                         "\n"
                         "# 100000\n"
                         "000000 100000\n"
                         "300000 100000\n"
                         "200000 100000\n"
                         "030000 100000\n"
                         "\n"
                         "# 200000\n"
                         "100000 200000\n";
    char *char_states[] = {
            "000000",
            "100000",
            "300000",
            "100000",
            "200000",
            "100000",
            "030000",
            "100000",
            "100000",
            "200000"
    };
    unsigned int n_tokens = 0;
    unsigned int arr_size = (unsigned int) (sizeof(char_states) / sizeof(char_states[0]));
    size_t string_size = strlen(char_states[0]);
    char **tokens = state_tokens(input_buffer, strlen(input_buffer) + 1, &n_tokens);
    TEST_ASSERT_TRUE(tokens);
    TEST_ASSERT_EQUAL_UINT(arr_size, n_tokens);
    for (int i = 0; i < arr_size; i++) {
        TEST_ASSERT_FALSE(memcmp(char_states[i], *(tokens + i), string_size));
        free(*(tokens + i));
    }
}

void setUp(void) {}

void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_parse_states);
    RUN_TEST(test_state_tokens);
    RUN_TEST(test_create_state);
    RUN_TEST(test_states_equal);
    RUN_TEST(test_print_state);
    RUN_TEST(test_create_transitions);
    RUN_TEST(test_transitions_equal);
    RUN_TEST(test_print_transition);
    RUN_TEST(test_filter_transitions);
    RUN_TEST(test_enumerate_transitions);
    RUN_TEST(test_init_state_string);
    return UNITY_END();
}