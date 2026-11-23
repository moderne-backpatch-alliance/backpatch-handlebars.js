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
            }, Error, /Invalid AST/);
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

    describe('GHSA-2w6w-674q-4c4q, GHSA-xhpv-hc6g-r9c6, GHSA-3mfm-83xf-c92r, GHSA-8r5x-fm3f-whwj: untrusted AST inputs', function() {
        if (!Handlebars.compile) {
            return;
        }

        function createInjectedProgram() {
            var loc = {
                source: null,
                start: { line: 1, column: 0 },
                end: { line: 1, column: 20 }
            };
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
                        loc: loc,
                        path: {
                            type: 'PathExpression',
                            data: false,
                            depth: 0,
                            parts: ['lookup'],
                            original: 'lookup',
                            loc: loc
                        },
                        params: [
                            {
                                type: 'PathExpression',
                                data: false,
                                depth: 0,
                                parts: [],
                                original: 'this',
                                loc: loc
                            },
                            {
                                type: 'NumberLiteral',
                                value: '{},{})) + (Function) + (({}',
                                original: 1,
                                loc: loc
                            }
                        ]
                    }
                ]
            };
        }

        it('should reject AST NumberLiteral type confusion in compile()', function() {
            // NumberLiteral.value is emitted as a raw JavaScript literal, so the
            // compiler rejects anything that is not a number.
            shouldThrow(function() {
                var template = Handlebars.compile(createInjectedProgram());
                template({});
            }, undefined, /Invalid AST: NumberLiteral value must be a number/);
        });

        it('should reject AST objects passed via dynamic partial lookup', function() {
            shouldThrow(function() {
                var template = Handlebars.compile('{{> (lookup . "payload")}}');
                template({
                    payload: createInjectedProgram()
                });
            }, undefined, /could not be found/);
        });

        it('should reject a non-integer param depth in stringParams mode', function() {
            // pushParam passes val.depth to the getContext opcode. In stringParams
            // mode, getContext stores the depth in lastContext, which contextName
            // interpolates into generated code as 'depths[' + depth + ']'. A depth
            // that is not a non-negative integer is therefore rejected.
            var loc = {
                source: null,
                start: { line: 1, column: 0 },
                end: { line: 1, column: 20 }
            };
            var maliciousAST = {
                type: 'Program',
                body: [
                    {
                        type: 'MustacheStatement',
                        escaped: true,
                        strip: { open: false, close: false },
                        loc: loc,
                        path: {
                            type: 'PathExpression',
                            data: false,
                            depth: 0,
                            parts: ['lookup'],
                            original: 'lookup',
                            loc: loc
                        },
                        params: [
                            {
                                type: 'PathExpression',
                                data: false,
                                depth: 'function(){throw new Error("INJECTION")}()',
                                parts: [],
                                original: '',
                                loc: loc
                            }
                        ]
                    }
                ]
            };

            shouldThrow(function() {
                var template = Handlebars.compile(maliciousAST, {
                    stringParams: true
                });
                template({});
            }, undefined, /Invalid AST: PathExpression depth must be a non-negative integer/);
        });

        it('should reject non-array blockParams', function() {
            // The compiler reads program.blockParams.length from the AST and
            // javascript-compiler.js interpolates that value verbatim into a
            // container.program(...) call. blockParams must therefore be an array
            // of strings, so that the length is always a safe integer.
            var maliciousAST = {
                type: 'Program',
                loc: { start: { line: 1, column: 0 } },
                body: [
                    {
                        type: 'BlockStatement',
                        path: {
                            type: 'PathExpression',
                            data: false,
                            depth: 0,
                            parts: ['rce'],
                            original: 'rce',
                            loc: { start: { line: 1, column: 0 } }
                        },
                        params: [],
                        program: {
                            type: 'Program',
                            blockParams: {
                                length: "(()=>{throw new Error('INJECTION')})()"
                            },
                            body: [],
                            loc: { start: { line: 1, column: 0 } }
                        },
                        openStrip: { open: false, close: false },
                        inverseStrip: { open: false, close: false },
                        closeStrip: { open: false, close: false },
                        loc: { start: { line: 1, column: 0 } }
                    }
                ]
            };

            shouldThrow(function() {
                var template = Handlebars.compile(maliciousAST, {
                    stringParams: true
                });
                template({});
            }, undefined, /Invalid AST: Program blockParams must be an array/);
        });

        it('should reject non-number NumberLiteral values in stringParams mode', function() {
            // In stringParams mode, pushStringParam emits any non-string param
            // value as a raw literal, and the code generator concatenates array
            // chunks verbatim. The NumberLiteral handler therefore rejects any
            // value that is not a number.
            var loc = {
                source: null,
                start: { line: 1, column: 0 },
                end: { line: 1, column: 20 }
            };
            var maliciousAST = {
                type: 'Program',
                body: [
                    {
                        type: 'MustacheStatement',
                        escaped: true,
                        strip: { open: false, close: false },
                        loc: loc,
                        path: {
                            type: 'PathExpression',
                            data: false,
                            depth: 0,
                            parts: ['helper'],
                            original: 'helper',
                            loc: loc
                        },
                        params: [
                            {
                                type: 'NumberLiteral',
                                value: ['(function(){throw new Error("INJECTION")})()'],
                                original: 1,
                                loc: loc
                            }
                        ]
                    }
                ]
            };

            shouldThrow(function() {
                var template = Handlebars.compile(maliciousAST, {
                    stringParams: true
                });
                template({});
            }, undefined, /Invalid AST: NumberLiteral value must be a number/);
        });
    });

    describe('GH-1595', function() {
      it('properties, that are required to be enumerable', function() {
        shouldCompileTo('{{constructor}}', {}, '');
        shouldCompileTo('{{__defineGetter__}}', {}, '');
        shouldCompileTo('{{__defineSetter__}}', {}, '');
        shouldCompileTo('{{__lookupGetter__}}', {}, '');
        shouldCompileTo('{{__proto__}}', {}, '');

        shouldCompileTo('{{lookup "constructor"}}', {}, '');
        shouldCompileTo('{{lookup "__defineGetter__"}}', {}, '');
        shouldCompileTo('{{lookup "__defineSetter__"}}', {}, '');
        shouldCompileTo('{{lookup "__lookupGetter__"}}', {}, '');
        shouldCompileTo('{{lookup "__proto__"}}', {}, '');
      });
    });

    describe('GH-1595 own non-enumerable properties', function() {
      var names = ['constructor', '__defineGetter__', '__defineSetter__', '__lookupGetter__', '__proto__'];

      function withOwn(name, enumerable) {
        var obj = {};
        Object.defineProperty(obj, name, { value: 'own', enumerable: enumerable });
        return obj;
      }

      it('are not resolved by a template lookup', function() {
        names.forEach(function(name) {
          shouldCompileTo('{{' + name + '}}', withOwn(name, false), '', name);
        });
      });

      it('are not resolved by the lookup helper', function() {
        names.forEach(function(name) {
          shouldCompileTo('{{lookup this "' + name + '"}}', withOwn(name, false), '', name);
        });
      });

      it('own enumerable properties are still resolved', function() {
        names.forEach(function(name) {
          shouldCompileTo('{{' + name + '}}', withOwn(name, true), 'own', name);
          shouldCompileTo('{{lookup this "' + name + '"}}', withOwn(name, true), 'own', name);
        });
      });
    });
});
