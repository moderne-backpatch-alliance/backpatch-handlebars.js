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
});
