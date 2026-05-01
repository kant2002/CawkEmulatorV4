using CawkEmulatorV4;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

// Collect all opcodes which we will use during fuzzing generation.
var opcodes = OpCodes.OneByteOpCodes.Where(_ => _.FlowControl == FlowControl.Next 
    && _.OperandType == OperandType.InlineNone
    && new[] { StackBehaviour.Push0, StackBehaviour.Push1 }.Contains(_.StackBehaviourPush)
    && new[] { StackBehaviour.Pop0, StackBehaviour.Pop1, StackBehaviour.Pop1_pop1 }.Contains(_.StackBehaviourPop));

var iterationsCount = args.Length > 0 ? int.Parse(args[0]) : 1000;
var seed = Environment.TickCount;
if (args.Length > 1)
{
    seed = int.Parse(args[1]);
}

// Generate a random sequence of opcodes. The number of opcodes is also random.
Console.WriteLine("Using seed: " + seed);
var random = new Random(seed);
TextWriter stringWriter = new StringWriter();
for (var i = 0; i < iterationsCount; i++)
{
    stringWriter = new StringWriter();
    var result = Validate(random, stringWriter);
    if (!result)
    {
        Console.WriteLine($"Mismatch detected!");
        Console.WriteLine(stringWriter.ToString());
        return 1;
    }
}

Console.WriteLine("Emulation successful, results match.");
return 0;

// Validates the randomly generated 
bool Validate(Random random, TextWriter logger)
{
    // Create a new module. The string passed in is the name of the module,
    // not the file name.
    var mod = new ModuleDefUser("MyModule.exe");
    mod.Kind = ModuleKind.Dll;

    // Add the module to an assembly
    var asm = new AssemblyDefUser("MyAssembly", new Version(1, 2, 3, 4), null, UTF8String.Empty);
    asm.Modules.Add(mod);

    // Add the startup type. It derives from System.Object.
    var startUpType = new TypeDefUser("My.Namespace", "Worker", mod.CorLibTypes.Object.TypeDefOrRef);
    startUpType.Attributes = TypeAttributes.NotPublic | TypeAttributes.AutoLayout |
                            TypeAttributes.Class | TypeAttributes.AnsiClass;
    // Add the type to the module
    mod.Types.Add(startUpType);

    // Create the entry point method
    var entryPoint = new MethodDefUser("FuzzingTask",
        MethodSig.CreateStatic(mod.CorLibTypes.Int32, new[]
        {
            mod.CorLibTypes.Int32,
            mod.CorLibTypes.Int32,
            mod.CorLibTypes.Int32,
            mod.CorLibTypes.Int32,
            mod.CorLibTypes.Int32,

            mod.CorLibTypes.Int32,
            mod.CorLibTypes.Int32,
            mod.CorLibTypes.Int32,
            mod.CorLibTypes.Int32,
            mod.CorLibTypes.Int32,
        }));
    entryPoint.Attributes = MethodAttributes.Private | MethodAttributes.Static |
                    MethodAttributes.HideBySig | MethodAttributes.ReuseSlot;
    entryPoint.ImplAttributes = MethodImplAttributes.IL | MethodImplAttributes.Managed;
    // Name the 1st argument (argument 0 is the return type)
    entryPoint.ParamDefs.Add(new ParamDefUser("A_0", 1));
    entryPoint.ParamDefs.Add(new ParamDefUser("A_1", 2));
    entryPoint.ParamDefs.Add(new ParamDefUser("A_2", 3));
    entryPoint.ParamDefs.Add(new ParamDefUser("A_3", 4));
    entryPoint.ParamDefs.Add(new ParamDefUser("A_4", 5));
    entryPoint.ParamDefs.Add(new ParamDefUser("A_5", 6));
    entryPoint.ParamDefs.Add(new ParamDefUser("A_6", 7));
    entryPoint.ParamDefs.Add(new ParamDefUser("A_7", 8));
    entryPoint.ParamDefs.Add(new ParamDefUser("A_8", 9));
    entryPoint.ParamDefs.Add(new ParamDefUser("A_9", 10));
    // Add the method to the startup type
    startUpType.Methods.Add(entryPoint);
    // Set module entry point
    mod.EntryPoint = entryPoint;

    // Add a CIL method body to the entry point method
    var epBody = new CilBody();
    //epBody.KeepOldMaxStack = true;
    for (var i = 0; i < 10; i++)
    {
        epBody.Variables.Add(new Local(mod.CorLibTypes.Int32));
    }

    entryPoint.Body = epBody;
    // Put argument on the stack.
    epBody.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
    epBody.Instructions.Add(OpCodes.Ldarg_1.ToInstruction());

    
    int stackSize = 2;
startGeneration:
    do
    {
        opcodes = stackSize < 100
            ? opcodes
            : opcodes.Where(_ => _.StackBehaviourPush == StackBehaviour.Push0).ToArray();
        var opcode = opcodes.ElementAt(random.Next(opcodes.Count()));
        var instruction = opcode.ToInstruction();
        epBody.Instructions.Add(instruction);
        instruction.UpdateStack(ref stackSize);
    }
    while (stackSize > 1);
    if (stackSize == 0)
    {
        epBody.Instructions.Add(OpCodes.Ldc_I4.ToInstruction(42));
        stackSize = 1;
        goto startGeneration;
    }

    // Return last stack value as the return value of the method.
    epBody.Instructions.Add(OpCodes.Ret.ToInstruction());

    // Save the assembly to a file on disk
    var memoryStream = new MemoryStream();
    mod.Write(memoryStream);
    memoryStream.Position = 0;
    //mod.Write(@"saved-assembly.dll");

    // Emulation
    var emulation = new Emulation(entryPoint);
    var inputValues =
        new object[] {
        random.Next(100), random.Next(100), random.Next(100), random.Next(100), random.Next(100),
        random.Next(100), random.Next(100), random.Next(100), random.Next(100), random.Next(100) };
    for (int i = 0; i < 10; i++)
    {
        var p = emulation.ValueStack.Parameters.First(_ => _.Key.Index == i).Key;
        emulation.ValueStack.Parameters[p] = inputValues[i];
    }
    emulation.ValueStack.Locals = [.. Enumerable.Range(0, 10).Select(_ => (dynamic)0)];

    logger.WriteLine("Parameters");
    for (int i = 0; i < 10; i++)
    {
        logger.WriteLine($"Parameter {i}: {inputValues[i]}");
    }
    logger.WriteLine();
    logger.WriteLine("Generated instructions");
    foreach (var instr in epBody.Instructions)
    {
        logger.WriteLine(instr);
    }
    logger.WriteLine();


    int emulatorResult = 0;
    Exception? emulationException = null;
    try
    {
        emulation.Emulate();
        var v = emulation.ValueStack.CallStack.Pop();
        emulatorResult = (int)v;
        logger.WriteLine($"Result {emulatorResult}");
    }
    catch (Exception ex)
    {
        emulationException = ex;
        logger.WriteLine($"Emulation failed with exception: {ex}");
    }


    var dynamicAssembly = System.Reflection.Assembly.Load(memoryStream.ToArray());
    var t = dynamicAssembly.DefinedTypes.ElementAt(0);
    int dotnetResult = 0;
    Exception? dotnetException = null;
    try
    {
        dotnetResult = (int)t.DeclaredMethods.ElementAt(0).Invoke(
            null,
            inputValues);
        logger.WriteLine($".NET Result {dotnetResult}");
    }
    catch (System.Reflection.TargetInvocationException tiex)
    {
        dotnetException = tiex.InnerException;
        logger.WriteLine($".NET failed with exception: {tiex.InnerException}");
    }
    catch (Exception ex)
    {
        dotnetException = ex;
        logger.WriteLine($".NET failed with exception: {ex}");
    }

    if (emulationException is not null && dotnetException is not null)
    {
        // Both threw exception, consider it as a match.
        return emulationException.GetType().FullName == dotnetException.GetType().FullName
            && emulationException.Message == dotnetException.Message;
    }

    return emulatorResult == dotnetResult;
}