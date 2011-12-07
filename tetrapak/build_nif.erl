-task({"build:nif", "Build the ejson NIF library"}).
-task({"clean:nif", "Clean the ejson NIF library"}).

run("build:nif", _) ->
    tetrapak:outputcmd(tetrapak:subdir("c_src"), "make", ["all"]);

run("clean:nif", _) ->
    tetrapak:outputcmd(tetrapak:subdir("c_src"), "make", ["clean"]).