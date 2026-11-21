describe('security issues', function() {
    describe('GH-1495: Prevent Remote Code Execution via constructor', function() {
        it('should not allow constructors to be accessed', function() {
            shouldCompileTo('{{lookup (lookup this "constructor") "name"}}', {}, '');

            shouldCompileTo('{{constructor.name}}', {}, '');
        });

        it('GH-1603: should not allow constructors to be accessed (lookup via toString)', function() {
          shouldCompileTo('{{lookup (lookup this (list "constructor")) "name"}}', [{}, {
              list: function(element) {
                return [element];
              }
          }], '');
        });


      it('should allow the "constructor" property to be accessed if it is enumerable', function() {
            shouldCompileTo('{{constructor.name}}', {'constructor': {
                'name': 'here we go'
            }}, 'here we go');
            shouldCompileTo('{{lookup (lookup this "constructor") "name"}}', {'constructor': {
                'name': 'here we go'
            }}, 'here we go');
        });

        it('should allow the "constructor" property to be accessed if it is enumerable', function() {
            shouldCompileTo('{{lookup (lookup this "constructor") "name"}}', {'constructor': {
                    'name': 'here we go'
                }}, 'here we go');
        });


        it('should allow prototype properties that are not constructors', function() {
            function TestClass() {
            }

            Object.defineProperty(TestClass.prototype, 'abc', {
                get: function() {
                    return 'xyz';
                }

            });

            shouldCompileTo('{{#with this as |obj|}}{{obj.abc}}{{/with}}',
                new TestClass(), 'xyz');
            shouldCompileTo('{{#with this as |obj|}}{{lookup obj "abc"}}{{/with}}',
                new TestClass(), 'xyz');

        });
    });

    describe('GH-1595', function() {
        it('properties, that are required to be enumerable', function() {
            shouldCompileTo('{{constructor.name}}', {}, '');
            shouldCompileTo('{{__defineGetter__.name}}', {}, '');
            shouldCompileTo('{{__defineSetter__.name}}', {}, '');
            shouldCompileTo('{{__lookupGetter__.name}}', {}, '');
            shouldCompileTo('{{__proto__.__defineGetter__.name}}', {}, '');

            shouldCompileTo('{{lookup this "constructor"}}', {}, '');
            shouldCompileTo('{{lookup this "__defineGetter__"}}', {}, '');
            shouldCompileTo('{{lookup this "__defineSetter__"}}', {}, '');
            shouldCompileTo('{{lookup this "__lookupGetter__"}}', {}, '');
            shouldCompileTo('{{lookup this "__proto__"}}', {}, '');
        });
    });

    describe('escapes template variables', function() {
        it('in compat mode', function() {
            shouldCompileTo("{{'a\\b'}}", [{ 'a\\b': 'c' }, undefined, undefined, { compat: true }], 'c');
        });

        it('in default mode', function() {
            shouldCompileTo("{{'a\\b'}}", { 'a\\b': 'c' }, 'c');
        });
        it('in default mode', function() {
            shouldCompileTo("{{'a\\b'}}", [{ 'a\\b': 'c' }, undefined, undefined, { strict: true }], 'c');
        });
    });

    describe('GHSA-2w6w-674q-4c4q, GHSA-xhpv-hc6g-r9c6, GHSA-3mfm-83xf-c92r: untrusted AST inputs', function() {
        if (!Handlebars.compile) {
            return;
        }

        function createInjectedProgram() {
            return {
                type: 'Program',
                body: [
                    {
                        type: 'MustacheStatement',
                        escaped: true,
                        strip: {
                            open: false,
                            close: false
                        },
                        path: {
                            type: 'PathExpression',
                            data: false,
                            depth: 0,
                            parts: ['lookup'],
                            original: 'lookup'
                        },
                        params: [
                            {
                                type: 'PathExpression',
                                data: false,
                                depth: 0,
                                parts: [],
                                original: 'this'
                            },
                            {
                                type: 'NumberLiteral',
                                value: '{},{})) + (Function) + (({}',
                                original: 1
                            }
                        ]
                    }
                ]
            };
        }

        it('should reject AST NumberLiteral type confusion in compile()', function() {
            shouldThrow(function() {
                var template = Handlebars.compile(createInjectedProgram());
                template({});
            }, Error, /Invalid AST/);
        });

        it('should reject AST objects passed via dynamic partial lookup', function() {
            shouldThrow(function() {
                var template = Handlebars.compile('{{> (lookup . "payload")}}');
                template({
                    payload: createInjectedProgram()
                });
            }, Error, /Invalid AST|could not be found/);
        });

        it('should reject a callable-looking AST object passed via dynamic partial lookup', function() {
            // `call: true` makes resolvePartial() return the object, so it reaches env.compile();
            // without it the lookup ends in "could not be found" and the validation is not reached.
            shouldThrow(function() {
                var template = Handlebars.compile('{{> (lookup . "payload")}}');
                template({
                    payload: {
                        call: true,
                        type: 'Program',
                        body: [
                            {
                                type: 'MustacheStatement',
                                escaped: true,
                                strip: {open: false, close: false},
                                path: {type: 'PathExpression', data: false, depth: '0', parts: ['this'], original: 'this'},
                                params: []
                            }
                        ]
                    }
                });
            }, Error, /Invalid AST: PathExpression.depth must be an integer/);
        });
    });

    describe('GHSA-9cx6-37pm-9jff: malformed decorators should fail safely', function() {
        if (!Handlebars.compile) {
            return;
        }

        it('should throw a controlled error for unknown decorators', function() {
            var template = Handlebars.compile('{{*notRegistered}}');
            shouldThrow(function() {
                template({});
            }, Error, /Missing decorator|not registered/);
        });
    });

    describe('GHSA-xw65-4hp5-5hc7: precompiled output must be safe in script tags', function() {
        var name = '</script><script>alert(1)</script>';

        function expectSafePrecompile(template, options) {
            if (Handlebars.precompile) {
                var precompiled = Handlebars.precompile(template, options);

                equal(/<(!--|\/?script)/i.test(precompiled), false);
                return precompiled;
            }
        }

        it('should escape script tag delimiters in static content', function() {
            var template = 'safe</ScRiPt ><span>alert(1)</script><SCRIPT>';
            var precompiled = expectSafePrecompile(template);
            if (precompiled) {
                equal(precompiled.indexOf('\\u003C/ScRiPt >') !== -1, true);
                equal(precompiled.indexOf('\\u003CSCRIPT>') !== -1, true);
            }
            shouldCompileTo(template, {}, template);
        });

        it('should escape HTML comment openers in static content', function() {
            var template = '<!--<script>';
            var precompiled = expectSafePrecompile(template);
            if (precompiled) {
                equal(precompiled.indexOf('\\u003C!--\\u003Cscript>') !== -1, true);
            }
            shouldCompileTo(template, {}, template);
        });

        it('should not escape other markup in static content', function() {
            var template = '<div class="a"><span>b</span></div><!- ->';
            var precompiled = expectSafePrecompile(template);
            if (precompiled) {
                equal(precompiled.indexOf('<div class=\\"a\\"><span>b</span></div><!- ->') !== -1, true);
            }
            shouldCompileTo(template, {}, template);
        });

        it('should escape script tag delimiters in string literals', function() {
            expectSafePrecompile('{{echo "' + name + '" key="' + name + '"}}');
            shouldCompileTo('{{{echo "' + name + '" key="' + name + '"}}}', [{}, {
                echo: function(value, options) {
                    return value + options.hash.key;
                }
            }], name + name);
        });

        it('should escape script tag delimiters in property lookups', function() {
            var input = {};
            input[name] = 'success';
            expectSafePrecompile('{{[' + name + ']}}');
            shouldCompileTo('{{[' + name + ']}}', input, 'success');
            expectSafePrecompile('{{foo.[' + name + ']}}');
            shouldCompileTo('{{foo.[' + name + ']}}', {foo: input}, 'success');
        });

        it('should escape script tag delimiters in data lookups', function() {
            var data = {};
            data[name] = 'success';
            expectSafePrecompile('{{@[' + name + ']}}');
            shouldCompileTo('{{@[' + name + ']}}', [{}, {}, {}, {}, data], 'success');
        });

        it('should escape script tag delimiters in helper and partial names', function() {
            var helpers = {};
            helpers[name] = function(options) {
                return options.fn(this);
            };
            var partials = {};
            partials[name] = 'success';
            expectSafePrecompile('{{#[' + name + ']}}x{{/[' + name + ']}}');
            shouldCompileTo('{{#[' + name + ']}}x{{/[' + name + ']}}', [{}, helpers], 'x');
            expectSafePrecompile('{{> [' + name + ']}}');
            shouldCompileToWithPartials('{{> [' + name + ']}}', [{}, {}, partials], true, 'success');
        });

        it('should escape script tag delimiters in compat mode lookups', function() {
            var input = {};
            input[name] = 'success';
            expectSafePrecompile('{{[' + name + ']}}', {compat: true});
            shouldCompileTo('{{[' + name + ']}}', [input, {}, {}, {compat: true}], 'success');
        });

        it('should escape script tag delimiters in tracked block param ids', function() {
            var template = '{{#each items as |item|}}{{{id item.[' + name + ']}}}{{/each}}';
            var item = {};
            item[name] = 'value';
            expectSafePrecompile(template, {trackIds: true});
            shouldCompileTo(template, [{items: [item]}, {
                id: function(value, options) {
                    return options.ids[0];
                }
            }, {}, {trackIds: true}], 'items.0.' + name);
        });
    });
});
