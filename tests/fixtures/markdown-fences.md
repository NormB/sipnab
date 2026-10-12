# Fence shapes both parsers must agree on

Read by `the_rust_and_python_fence_parsers_agree` in
`tests/doc_commands_run_test.rs`, beside every page that test walks. Each
shape below is one a gate in this repository once read wrongly.

```bash
sipnab -N -I capture.pcap
```

1. A fence indented three spaces under a list item:

   ```bash
   sipnab -N -I capture.pcap --json
   ```

2. Six spaces under a nested item. A renderer reads a fence here, and
   neither parser does, because neither reads list structure;
   `no_command_sits_in_a_fence_the_parsers_cannot_see` holds that gap shut:

      ```bash
      sipnab -N -I nested.pcap
      ```

    ```bash
    four spaces is an indented code block
    ```

~~~text
a tilde fence holding a backtick line
```
still inside the tilde fence
~~~

````markdown
```bash
a fence shown inside a longer fence
```
````

```Bash,ignore
an info string with a comma
```

``not a fence``

```console
an unclosed fence runs to the end of the document
