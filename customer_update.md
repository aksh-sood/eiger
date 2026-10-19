# A Security Update on Iggy

During a security review of Iggy, our banking assistant, we found a weakness in how it handled notes that users can save for it to refer to. A carefully written note could be mistaken for an instruction, which could make Iggy give a misleading answer to a later, related question.

We have changed Iggy so that it keeps verified bank information separate from anything users submit, and labels user notes as background information, not instructions. We also added a check to keep internal documents out of answers for people who aren't allowed to see them.

We have found no evidence that any customer data was exposed, and there is nothing you need to do. If anything Iggy tells you ever looks wrong, please contact us. Thank you for banking with us.
