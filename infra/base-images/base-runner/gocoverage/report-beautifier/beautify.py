#!/usr/bin/env python3
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

import html
import os
import sys
import shutil
import httpx
from bs4 import BeautifulSoup
import validators

DOC_HEADER = """
    <!DOCTYPE html>
    <html>

    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link href="https://fonts.cdnfonts.com/css/noto-sans" rel="stylesheet">
        <title>common: Go Coverage Report</title>
        <style>
        body {
        margin: 0;
        }
            ul,
            .fileUL {
                list-style-type: none;
            }
            .fileUL {
                margin: 0;
                padding: 35px 10px 15px 15px;
            }
            .directory {
                cursor: default;
                user-select: none;
            }

            .directory::before {
                content: "›";
                color: #919cae;
                display: inline-block;
                margin-right: 6px;
            }

            .caret-down::before {
                transform: rotate(90deg);
            }
            .nested {
                height: 0;
                max-height: 0;
                overflow-y: hidden;
                transition: height 2s linear;
            }

            .nested.active {
                height: var(--height);
                max-height: 999999px;
                transition: height 2s linear;
            }
            body {
                color: rgb(80,80,80);
            }
            #content {
                /*margin-top: 2.5vh;*/
            }
            #legend span {
                margin: 0 5px;
            }
            #legend {
                background: black;
            }
            .file-tree, #code-area {
                height: calc(100vh + 30px);
                width: 100%;
                float: left;
                overflow: scroll;
            }
            .file-tree {
                font-family: 'Noto Sans', sans-serif;
                /*padding-top: 35px;*/
                cursor: default;
                background: #19202a;
            }
            .source-file {
                color: #919cae;
                font-size: .9rem;
            }
            .source-file:hover {
                cursor: pointer;
            }
            .directory {
                color: #919cae;
                font-size: .9rem;
            }
            .directory:hover {
                cursor: pointer;
            }
            #code-area {
                background: #1d242f;
            }
            pre, #legend {
                color: rgb(80,80,80);
                font-family: Menlo, monospace;
                font-weight: bold;
            }
            pre {
                line-height: 8px;
                overflow-y: hidden;
                padding-top: 15px;
                padding-left: 15px;
                padding-bottom: 15px;
            }
            pre::-webkit-scrollbar { display: none; }
            ul {
                padding-inline-start: 10px;
            }
            .selected {
                background-color: #919cae;
                color: white;
            }

            /* Taken from native Go source file */
            .cov0 { color: rgb(192, 0, 0) }
            .cov1 { color: rgb(128, 128, 128) }
            .cov2 { color: rgb(116, 140, 131) }
            .cov3 { color: rgb(104, 152, 134) }
            .cov4 { color: rgb(92, 164, 137) }
            .cov5 { color: rgb(80, 176, 140) }
            .cov6 { color: rgb(68, 188, 143) }
            .cov7 { color: rgb(56, 200, 146) }
            .cov8 { color: rgb(44, 212, 149) }
            .cov9 { color: rgb(32, 224, 152) }
            .cov10 { color: rgb(20, 236, 155) }
            .container-fluid {
                width: 100%;
                padding-right: 15px;
                padding-left: 15px;
                margin-right: auto;
                margin-left: auto;
            }
            .row {
                display: -ms-flexbox;
                display: flex;
                -ms-flex-wrap: wrap;
                flex-wrap: wrap;
                margin-right: -15px;
                margin-left: -15px;
            }
        </style>
    </head>
    """

def download_file(url, save_to):
    content = httpx.get(url).content
    with open(save_to, 'wb') as f:
        f.write(content)


def extract_directories_and_contents(input_file):
    content = open(input_file, 'r').read()
    soup = BeautifulSoup(content, 'html.parser')
    all_files = soup.find_all("option")

    for _, file in enumerate(all_files, start=1):
        option_id = file['value']

        # Remove OSS-Fuzz $OUT dirs from filetree
        name = file.text.split("/workspace/out/libfuzzer-coverage-x86_64/src", 1)[-1]
        file_contents = soup.find("pre", {"id": option_id}).decode_contents()
        folder_name = "/".join(name.split("/")[:-1])
        file_name = name.split("/")[-1]

        os.makedirs("./files" + folder_name, exist_ok=True)
        with open("./files" + folder_name + "/" + file_name, 'w') as f:
            f.write(file_contents)

# Creates the file tree used for the left side of the screen
def create_tree(path, html=""):
    for file in sorted(os.listdir(path)):
        rel = path + "/" + file
        if os.path.isdir(rel):
            html += """
            <li><span class="directory">%s</span>
            <ul class="nested">
            """ % (file)
            html += create_tree(rel)
            html += "</ul></li>"
        else:
            with open(os.path.join(path, file), "r") as content:
                html += "<li class='source-file'><pre style='display: none;'>%s</pre>%s</li>" % (
                    "\n".join(content.readlines()), file)
    return html


def get_doc_body():
    return """
    <body style="display:flex">
        <div class="container-fluid">
            <div class="row" id="content">
                <div class="file-tree" style="flex:2">
                    <ul class="fileUL">
                        %s
                    </ul>
                </div>
                <div class="" style="flex:10" id="code-area"></div>
            </div>
        </div>
        <script>
            var toggler = document.getElementsByClassName("directory");
            var i;

            for (i = 0; i < toggler.length; i++) {
                toggler[i].addEventListener("click", function () {
                    this.parentElement.querySelector(".nested").classList.toggle("active");
                    this.classList.toggle("caret-down");
                });
            }
            var clickFunc = function() {
                var selected = document.getElementsByClassName("selected");
                for (let i=0; i < selected.length; i++){
                    selected[i].classList.remove("selected");
                }
                this.classList.add("selected");
                var code_area = document.getElementById("code-area");
                var code = this.getElementsByTagName('pre')[0];
                code_area.scrollTo(0, 0);
                code_area.innerHTML = "<pre>" + code.innerHTML + "</pre>";
            };

            let sourceFiles = document.getElementsByClassName("source-file");

            for (var i = 0; i < sourceFiles.length; i++) {
                sourceFiles[i].addEventListener('click', clickFunc, false);
            }

        </script>
    </body>
    """ % (create_tree("files"))


def clean_up():
    shutil.rmtree("./files")


def export(output_file):
    with open(output_file, "w") as output:
        output.writelines([DOC_HEADER, get_doc_body()])

def is_url(input_file):
    if  validators.url(input_file):
        return True
    return False

def main(input_file, output_file="output.html", *args, **kwargs):
    try:
        if is_url(input_file):
            # download coverage file
            url, input_file = input_file, "input.html"
            download_file(url, input_file)
        extract_directories_and_contents(input_file)
        export(output_file)
        clean_up()
    except Exception as e:
        print("An error occurred")
        print(e)

# Takes minimum 1 arg and optionally a second arg.
# Arg 1 (Required): The original Golang coverage report
# Arg 2 (Optional): The output filename
# The input file (arg1) can be either a path to a local file
# or a URL.
if __name__ == '__main__':
    args = sys.argv[1:]
    if not args:
        print("Report file or url not provided")
        print("Usage:\n\tpython generator.py <input_file> <optional_output_file>")
        sys.exit(1)
    main(*args)
