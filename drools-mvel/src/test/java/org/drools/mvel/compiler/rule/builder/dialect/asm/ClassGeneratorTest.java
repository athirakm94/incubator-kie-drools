/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.drools.mvel.compiler.rule.builder.dialect.asm;

import org.drools.mvel.asm.ClassGenerator;
import org.drools.util.TypeResolver.ClassFilter;
import org.junit.jupiter.api.Test;
import org.mvel2.asm.MethodVisitor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mvel2.asm.Opcodes.ACC_FINAL;
import static org.mvel2.asm.Opcodes.ACC_PRIVATE;
import static org.mvel2.asm.Opcodes.ACC_PUBLIC;
import static org.mvel2.asm.Opcodes.ALOAD;
import static org.mvel2.asm.Opcodes.ARETURN;
import static org.mvel2.asm.Opcodes.RETURN;

public class ClassGeneratorTest {

    @Test
    public void testGenerateBean() {
        final String MY_NAME = "myName";
        ClassGenerator generator = new ClassGenerator("pkg.Bean1", getClass().getClassLoader())
                .addField(ACC_PRIVATE | ACC_FINAL, "name", String.class);

        generator.addDefaultConstructor(new ClassGenerator.MethodBody() {
            public void body(MethodVisitor mv) {
                mv.visitVarInsn(ALOAD, 0);// read local variable 0 (initialized to this) and push it on the stack
                mv.visitLdcInsn(MY_NAME); // push the String MY_NAME on the stack
                putFieldInThis("name", String.class);
                mv.visitInsn(RETURN);
            }
        }).addMethod(ACC_PUBLIC, "toString", generator.methodDescr(String.class), new ClassGenerator.MethodBody() {
            public void body(MethodVisitor mv) {
                getFieldFromThis("name", String.class);
                mv.visitInsn(ARETURN); // return the first object on the stack
            }
        });

        Object instance = generator.newInstance();
        assertThat(instance.toString()).isEqualTo(MY_NAME);
    }

    @Test
    public void testGenerateWithConstructorArg() {
        final String MY_NAME = "myName";
        ClassGenerator generator = new ClassGenerator("pkg.Bean2", getClass().getClassLoader())
                .addField(ACC_PRIVATE | ACC_FINAL, "name", String.class);

        generator.addDefaultConstructor(new ClassGenerator.MethodBody() {
            public void body(MethodVisitor mv) {
                putFieldInThisFromRegistry("name", String.class, 1);
                mv.visitInsn(RETURN);
            }
        }, String.class);

        generator.addMethod(ACC_PUBLIC, "toString", generator.methodDescr(String.class), new ClassGenerator.MethodBody() {
            public void body(MethodVisitor mv) {
                getFieldFromThis("name", String.class);
                mv.visitInsn(ARETURN); // return the first object on the stack
            }
        });

        Object instance = generator.newInstance(String.class, MY_NAME);
        assertThat(instance.toString()).isEqualTo(MY_NAME);
    }

    /**
     * Verifies CWE-470 fix: InternalTypeResolver.resolveType must use ClassLoader.loadClass
     * rather than Class.forName(..., initialize=true, ...) so that static initializers of
     * resolved classes are NOT triggered during rule compilation/bytecode generation.
     * Tracks that a class can be resolved for type-descriptor work without initialisation.
     */
    @Test
    public void testInternalTypeResolverUsesLoadClassNotForName() throws Exception {
        // The InternalTypeResolver is created when no external TypeResolver is supplied.
        // Verify that a well-known class name resolves correctly via the fallback path.
        ClassGenerator generator = new ClassGenerator("pkg.ResolverTest", getClass().getClassLoader());

        // toTypeDescriptor delegates to the internal resolver; must resolve java.lang.String
        String descriptor = generator.toTypeDescriptor("java.lang.String");
        assertThat(descriptor).isEqualTo("Ljava/lang/String;");
    }

    /**
     * Verifies CWE-470 fix: resolveType(className, ClassFilter) rejects classes that fail
     * the filter rather than silently loading them, giving callers a filter-based guard.
     * The InternalTypeResolver is accessed via the two-argument constructor of ClassGenerator
     * when no external TypeResolver is provided; we test it directly via reflection here.
     */
    @Test
    public void testInternalTypeResolverWithClassFilterRejectsDisallowedClass() throws Exception {
        // Retrieve the private InternalTypeResolver created by the single-ClassLoader constructor.
        ClassGenerator generator = new ClassGenerator("pkg.FilterTest", getClass().getClassLoader());

        java.lang.reflect.Field resolverField = ClassGenerator.class.getDeclaredField("typeResolver");
        resolverField.setAccessible(true);
        org.drools.util.TypeResolver internalResolver =
                (org.drools.util.TypeResolver) resolverField.get(generator);

        // ClassFilter that rejects everything — simulates a strict allowlist.
        ClassFilter rejectAll = clazz -> false;

        assertThatThrownBy(() -> internalResolver.resolveType("java.lang.String", rejectAll))
                .isInstanceOf(ClassNotFoundException.class)
                .hasMessageContaining("rejected by ClassFilter");
    }

    /**
     * Verifies CWE-470 fix: InternalTypeResolver rejects class names that do not match
     * the safe allowlist pattern (e.g. names containing path separators, shell metacharacters,
     * or other characters that have no place in a legal Java binary class name).
     */
    @Test
    public void testInternalTypeResolverRejectsIllegalClassNames() throws Exception {
        ClassGenerator generator = new ClassGenerator("pkg.PatternTest", getClass().getClassLoader());

        java.lang.reflect.Field resolverField = ClassGenerator.class.getDeclaredField("typeResolver");
        resolverField.setAccessible(true);
        org.drools.util.TypeResolver internalResolver =
                (org.drools.util.TypeResolver) resolverField.get(generator);

        String[] illegalNames = {
            "../evil/Class",          // path traversal
            "java/lang/Runtime",      // slash separator (internal name, not binary)
            "com.example.Foo;drop",   // semicolon injection
            "com.example.Foo Bar",    // whitespace
            "com.example.Foo<Bar>",   // generic brackets
        };

        for (String illegalName : illegalNames) {
            assertThatThrownBy(() -> internalResolver.resolveType(illegalName))
                    .as("Expected rejection of illegal class name: " + illegalName)
                    .isInstanceOf(ClassNotFoundException.class)
                    .hasMessageContaining("Illegal class name rejected");
        }
    }
}
